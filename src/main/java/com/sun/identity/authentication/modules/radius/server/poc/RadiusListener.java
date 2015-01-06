package com.sun.identity.authentication.modules.radius.server.poc;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.State;
import com.sun.identity.authentication.modules.radius.client.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Listens for requests from RADIUS clients and returns corresponding responses.
 *
 * Created by markboyd on 6/18/14.
 */
public class RadiusListener {

    /**
     * Formatter for writing current timestamp to console.
     */
    private static final SimpleDateFormat formatter = new SimpleDateFormat("yyyyy-mm-dd hh:mm:ss SSS");

    /**
     * Used for logging timestamp of a line item.
     *
     * @return
     */
    public static String getTimeStampAsString() {
        return formatter.format(new Date()) + " ";
    }

    /**
     * The maximum radius packet size as per section 3 of rfc 2865.
     */
    public static final int MAX_PACKET_SIZE = 4096;

    /**
     * The assigned port for the port for RADIUS authentication and authorization as per rfc 2865.
     */
    public static final int DEFAULT_AUTH_PORT = 1812;

    /**
     * Shared objects used in the server for all requests.
     */
    private final Context serverData = new Context();

    /**
     * The configured default state and flows between states based upon transitions and their triggers.
     */
    private Flow flow = null;

    /**
     * Indicates any request should be mapped to the single defined client if true. this is only be used
     * for testing and should be false in a production environment as well as support multiple clients.
     */
    public static final boolean allowAnyClientIp = true;
    public static InetAddress clientIp = InetAddress.getLoopbackAddress(); // for testing from local calls

    public static String clientSecret = "radius";

    //public static final String PAIRING_DEVICE = "submit-pairing-phrase";
    //public static final String PENDING_DEVICE_RESPONSE = "awaiting-device-response";


    // private Map<String, String> passwords = new HashMap<String, String>();

    /**
     * The port on which to listen for RFC 2865 requests.
     */
    private final int authPort;

    public RadiusListener(int authPort, Flow flow) throws IOException {
        this.authPort = authPort;
        this.flow = flow;
        serverData.channel = DatagramChannel.open();
        if (authPort == -1) { // assign to any avialable port. typically for testing only.
            serverData.channel.bind(null);
        }
        else {
            serverData.channel.socket().bind(new InetSocketAddress(authPort));
        }
        System.out.println();
        System.out.println(getTimeStampAsString() + "RADIUS AuthN/Z Server Is Ready");
        System.out.println(getTimeStampAsString() + "Listening Port   : " + authPort);
        if (allowAnyClientIp) {
            System.out.println(getTimeStampAsString() + "Defined Client   : Any - WARNING: lock this down in production!"); // + clientIp);
        }
        else {
            System.out.println(getTimeStampAsString() + "Defined Client   : " + clientIp);
        }
        System.out.println(getTimeStampAsString() + "Shared Secret    : " + clientSecret);
        //System.out.println("Toopher Consumer : " + toopherConsumerName);
        System.out.println();

        //passwords.put("alice", "alicepwd");
        //passwords.put("sam", "sampwd");
    }

    /**
     * Returns the port on which this listener is bound and recieves requests.
     *
     * @return
     */
    public int getPort() {
        return serverData.channel.socket().getPort();
    }

    /**
     * Blocking call that listens for incoming datagrams and performs simple validation before returning for processing.
     *
     * @return
     */
    private RequestInfo awaitRequest() {
        // assure big-endian (network) byte order for our buffer
        ByteBuffer bfr = ByteBuffer.allocate(MAX_PACKET_SIZE);
        bfr.order(ByteOrder.BIG_ENDIAN);
        RequestInfo req = new RequestInfo();

        while (true) {
            // see if we have a datagram packet waiting for us
            try {
                bfr.clear();
                req.addr = (InetSocketAddress) serverData.channel.receive(bfr);
                if (req.addr == null) {
                    continue; // no datagram was available
                }
            } catch (IOException e) {
                System.out.println(getTimeStampAsString() + "Exception Receiving packet. Ignoring.");
                e.printStackTrace();
                continue;
            }
            // start timer
            long start = System.currentTimeMillis();

            // prepare buffer for draining
            bfr.flip();

            // parse into a packet object
            try {
                req.pkt = PacketFactory.toPacket(bfr);
            }
            catch(Exception e) {
                System.out.println(getTimeStampAsString() + "Error in parsing received packet. Ignoring.");
                e.printStackTrace();
                continue;
            }
            req.start = start;
            System.out.println(getTimeStampAsString() + "----> " + req.pkt.getType() + " - " + req.pkt.getIdentifier() + " from "
                    + req.addr.getAddress().toString()
                    + (allowAnyClientIp ? " - WARNING: Allowing requests from any client." : ""));
            Send.dumpAttributesToStdOut(req.pkt);

            // verify client ip address
            if (!allowAnyClientIp) {
                if (!req.addr.getAddress().equals(clientIp)) {
                    System.out.println(getTimeStampAsString() + "Request IP Doesn't match registered client: " + clientIp + ". Ignoring.");
                    continue;
                }
                // set the secret of the client that is connecting (only one for now)
                req.clientSecret = clientSecret;
            }
            else {
                req.clientSecret = clientSecret;
            }

            // verify packet type for this port
            if (req.pkt.getType() != PacketType.ACCESS_REQUEST) {
                System.out.println(getTimeStampAsString() + " type: " + req.pkt.getType() + ". Ignoring.");
                continue;
            }
            return req;
        }
    }

    /**
     * Walks the packet's included attributes and extracts data that we are expecting to use.
     *
     * @param req
     */
    private void loadDataFromPacket(RequestInfo req) {
        req.authctr = req.pkt.getAuthenticator();
        AttributeSet atts = req.pkt.getAttributeSet();
        int len = atts.size();

        // initialize state for when there won't be any incoming state attribute, ie: when starting authentication.
        // state only comes in via an access-challenge response from us
        req.stateHolder = new StateHolder(flow.getDefaultState());

        for(int i=0; i<len; i++) {
            Attribute a = atts.getAttributeAt(i);
            AttributeType t = AttributeType.getType(a.getType());

            if (t == null) {
                // if we don't know what type it is we certainly ain't looking for data contained in it. :-)
                continue;
            }

            switch(t) {
                case USER_NAME:
                    req.username = ((UserNameAttribute) a).getName();
                    break;
                case USER_PASSWORD:
                    try {
                        UserPasswordAttribute up = (UserPasswordAttribute) a;
                        req.credential = ((UserPasswordAttribute)a).extractPassword(req.authctr, clientSecret);
                    } catch (IOException e) {
                        System.out.println(getTimeStampAsString() + "problem extracting password field from packet");
                        e.printStackTrace();
                    }
                    break;
                case STATE:
                    req.stateHolder = new StateHolder(((StateAttribute) a).getString());
                    break;
            }
        }
    }

    /**
     * Listens for requests and sends responses implementing the following state machine. The values before the colons
     * are the state included in an incoming request which is non-existent for the initial request and is the
     * state in a challenge response that precipitated this incoming request.
     *
     *
     * <pre>
     *     no-state (no pairing already for user) : solicit pairing phrase from user by issuing challenge response for GET_PAIRING_PHRASE
     *     no-state (pairing exists for user) : send authorization request to device and solicit access authorization on device by issuing challenge response for PENDING_DEVICE_APPROVAL
     *
     *     GET_PAIRING_PHRASE : pair the device and solicit pairing authorization on device by issuing challenge response for PENDING_PAIRING_COMPLETION
     *     PENDING_PAIRING_COMPLETION : send authorization request to device and solicit access authorization on device by issuing challenge response for PENDING_DEVICE_APPROVAL
     *     PENDING_DEVICE_APPROVAL : obtain device aproval/denial and issue corresponding allow/deny
     * </pre>
     */
    public void listen() {
        ByteBuffer bfr = ByteBuffer.allocate(MAX_PACKET_SIZE);

        // assure big-endian (network) byte order
        bfr.order(ByteOrder.BIG_ENDIAN);
        boolean terminated = false;

        while (!terminated) {
            try {
                // listen for valid incoming access-request
                RequestInfo req = this.awaitRequest();

                // extract usr/pwd/[state]
                this.loadDataFromPacket(req);

                // now walk the state's configured transitions and see if one is triggered and execute it
                State state = req.stateHolder.getState();
                Flow.StateCfg scfg = flow.getConfig(state);
                State next = null;

                for(Transition t : scfg.getTransitions()) {
                    if (t.isTriggered(req, serverData)) {
                        next = t.getNextState();
                        req.stateHolder.setState(next); // next state must be set here so that .then() processors get target state values like message
                        Flow.StateCfg nextCfg = flow.getConfig(next);

                        t.execute(req, serverData, nextCfg.getMessage());
                        break;
                    }
                }

                if (next == null) {
                    System.out.println(getTimeStampAsString() + "WARNING: no next state identified for incoming request with state " + state + " and user " + req.username + ". Ignoring.");
                    // handle this
                }
            }
            catch(Throwable t) {
                System.out.println(getTimeStampAsString() + "------- Unable to process request");
                t.printStackTrace();
                System.out.println(getTimeStampAsString() + "------- Resume Listening");
            }
        }
    }

    /*
    Entry point into Proof of Concept.
     */
    public static void main(String[] args) throws IOException {
        // first define how our server will behave
        // when we support multiple clients we would need a custom Flows object for each.
        //Flow flow = SampleFlows.SMS_PROD_DEMO_NO_PROVISIONING.getFlow();

        Flow allowAllFlow = new Flow()
                .addDefaultState(State.STARTING)

                .add(State.STARTING, "",
                        // if password starts with '+' and has the length of a phone number we will attempt to set up
                        // a new pairing.
                        Transition.to(State.DONE)
                                .when(new Trigger() {
                                    @Override
                                    public boolean isTriggered(RequestInfo req, Context ctx) {
                                        return true;
                                    }
                                })
                                .then(Send.radiusAccessAllowed())
                )
                .add(State.DONE, "");

        Flow denyAllFlow = new Flow()
                .addDefaultState(State.STARTING)

                .add(State.STARTING, "",
                        // if password starts with '+' and has the length of a phone number we will attempt to set up
                        // a new pairing.
                        Transition.to(State.DONE)
                                .when(new Trigger() {
                                    @Override
                                    public boolean isTriggered(RequestInfo req, Context ctx) {
                                        return true;
                                    }
                                })
                                .then(Send.radiusAccessReject("denying everyone"))
                )
                .add(State.DONE, "");

        boolean allowAll = args.length == 1 && args[0].equals("allow-all");

        Flow flow = (allowAll ? allowAllFlow : denyAllFlow);

        // now start it up and tell it to start listening.
        new RadiusListener(1815, flow).listen();
    }
}


