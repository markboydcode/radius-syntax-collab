package com.sun.identity.authentication.modules.radius.server;

import com.sun.identity.authentication.modules.radius.client.*;
import com.sun.identity.authentication.modules.radius.server.config.ClientConfig;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Holds context information about a received radius request being processed and provides the means for a client's
 * handler to send a response.
 *
 * Created by markboyd on 11/24/14.
 */
public class RadiusRequestContext {
    private static final Logger cLog = Logger.getLogger(RadiusRequestContext.class.getName());

    /**
     * The configuration object delineating the client that sent the request.
     */
    public final ClientConfig clientConfig;

    /**
     * The channel through which the request was received.
     */
    public final DatagramChannel channel;

    /**
     * The originating host and port of the request.
     */
    public final InetSocketAddress source;

    /**
     * After the call to a client's declared AccessRequestHandler class this variable will indicate if the handler
     * called RadiusResponseHandler's send method or not.
     */
    public boolean sendWasCalled;

    /**
     * The authenticator from the request for use in producing the response's authenticator field at send time.
     */
    public Authenticator requestAuthenticator;

    /**
     * The packet id from the request for embedding in the response.
     */
    public short requestId;

    /**
     * Constructs the reponse handler.
     *
     * @param clientConfig
     * @param channel
     * @param source
     */
    public RadiusRequestContext(ClientConfig clientConfig, DatagramChannel channel, InetSocketAddress source) {
        this.channel = channel;
        this.source = source;
        this.clientConfig = clientConfig;
    }

    /**
     * Log packet's attributes in raw hex and read-able chars (where possible)
     * @param pkt
     */
    public void logPacketContent(Packet pkt, String preamble) {
        cLog.log(Level.INFO, preamble + "\n" + getPacketRepresentation(pkt));
    }

    /**
     * Formats a textual representation of the contents of a packet.
     *
     * @param pkt
     * @return
     */
    public static String getPacketRepresentation(Packet pkt) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        String packetType = null;
        Class clazz = pkt.getClass();
        if (clazz == AccessRequest.class) {
            packetType = "ACCESS_REQUEST";
        }
        else if (clazz == AccessReject.class) {
            packetType = "ACCESS_REJECT";
        }
        else if (clazz == AccessAccept.class) {
            packetType = "ACCESS_ACCEPT";
        }
        else if (clazz == AccessChallenge.class) {
            packetType = "ACCESS_CHALLENGE";
        }
        else {
            packetType = pkt.getClass().getSimpleName();
        }
        pw.println("  " + packetType + " [" + pkt.getIdentifier() + "]");
        AttributeSet atts = pkt.getAttributeSet();
        for(int i=0; i<atts.size(); i++) {
            Attribute a = atts.getAttributeAt(i);
            pw.println("    - " + a);
        }
        pw.flush();
        return sw.toString();
    }

    /**
     * Takes the passed-in packet, injects the ID of the request and a response authenticator and sends it to the
     * source of the request.
     *
     * @param response
     */
    public void send(Packet response) {
        if (sendWasCalled) {
            cLog.log(Level.WARNING, "Handler class '" + clientConfig.clazz.getSimpleName()
                    + "' declared for client " + clientConfig.name + " called send more than once.");
            return;
        }
        sendWasCalled = true;

        if (response == null) {
            cLog.log(Level.SEVERE, "Handler class '" + clientConfig.clazz.getSimpleName()
                    + "' declared for client " + clientConfig.name + " attempted to send a null response. Rejecting access.");
            send(new AccessReject());
            return;
        }

        // inject the id and authenticator
        response.setIdentifier(requestId);
        injectResponseAuthenticator(response);

        if (clientConfig.logPackets) {
            logPacketContent(response, "\nPacket to " + clientConfig.name + ":");
        }
        ByteBuffer reqBuf = ByteBuffer.wrap(response.getData());

        try {
            channel.send(reqBuf, source);
        } catch (IOException e) {
            cLog.log(Level.SEVERE, "Unable to send response to " + clientConfig.name + ".", e);
        }
    }

    /**
     * Converts to the on-the-wire bytes and hands them to the channel for sending via a ByteButter.
     *
     * @param response
     */
    private void sendToSource(Packet response) {

    }

    /**
     * Crafts the response authenticator as per the Response Authenticator paragraph of section 3 of rfc 2865 and
     * injects into the response packet thus defining the authenticity and integrity of this response relative to its request.
     *
     * @param response
     */
    private void injectResponseAuthenticator(Packet response) {
        response.setAuthenticator(requestAuthenticator);
        byte[] onTheWireFormat = response.getData();

        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            // ignore. if happens let it die since this jvm is hosed
        }
        md5.update(onTheWireFormat);
        md5.update(clientConfig.secret.getBytes());
        byte[] hash = md5.digest();

        ResponseAuthenticator ra = new ResponseAuthenticator(hash);

        // now replace the req authnctr fields used for generating the response authntctr fields
        response.setAuthenticator(ra);
    }

}
