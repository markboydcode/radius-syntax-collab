package com.sun.identity.authentication.modules.radius.server;

import com.sun.identity.authentication.modules.radius.RADIUSServer;
import com.sun.identity.authentication.modules.radius.client.ChallengeException;
import com.sun.identity.authentication.modules.radius.client.RadiusConn;
import com.sun.identity.authentication.modules.radius.client.RejectException;
import com.sun.identity.authentication.modules.radius.server.poc.RadiusListener;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.DatagramChannel;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Uses openAM's radius authentication module code to fire off requests against the RadiusListener test radius server
 * crafted by modifying and enhancing openAM's radius client code.
 *
 * Created by markboyd on 6/18/14.
 */
public class TestServer {

    //@Test
    public void test() throws IOException, RejectException, NoSuchAlgorithmException, ChallengeException {
        // TODO make this a real integration test by spinning up a suitable flow for simple authentication
        // then start a thread for running the listener and have code in the flow watching for specific
        // usernames and return different responses to test all packet building and marshalling and then
        // verify client side that we get the expected responses.

        // start up a RadiusListener with a custom flow for our test
//        Flow flow = new Flow()
//                .add(S)
        // set up a set the set of servers needed by the openAM radius client codebase
        Set<RADIUSServer> secondaryServers = new LinkedHashSet<RADIUSServer>();
        Set<RADIUSServer> primaryServers = new LinkedHashSet<RADIUSServer>();

        //primaryServers.add(new RADIUSServer("l8027.ldschurch.org", RadiusListener.DEFAULT_AUTH_PORT));
        primaryServers.add(new RADIUSServer("localhost", RadiusListener.DEFAULT_AUTH_PORT));

        String sharedSecret = "password1";
        int iTimeOut = 5; // seconds
        int healthCheckInterval = 5; // seconds

        RadiusConn conn = new RadiusConn(primaryServers, secondaryServers,
                sharedSecret, iTimeOut, healthCheckInterval);

        int loop = 1;
        for(int i=0; i<loop; i++) {
            try {
                conn.authenticate( "boydmr", "secret");
            }
            catch (RejectException re) {
                System.out.println("--- REJECTED: boydmr");
            }

            try {
                conn.authenticate( "alice", "alicepwd");
                System.out.println("--- ACCEPTED: alice");
            }
            catch (RejectException re) {
                System.out.println("--- REJECTED: alice");
            }

            try {
                conn.authenticate( "sam", "wrong");
                System.out.println("--- ACCEPTED: sam");
            }
            catch (RejectException re) {
                System.out.println("--- REJECTED: sam");
            }
        }
    }

    public static class Data {
        DatagramChannel serverChan = null;
        String state = "starting";
        SocketAddress clientAddr;
        ByteBuffer serverBuf;
        public boolean listenerTerminated = false;
        public int serverPort = -1;
        List<Thread> responders = new ArrayList<Thread>();
    }

    //@Test
    public void testformat() {
        System.out.println(MessageFormat.format("RADIUS-{0,number,#####}-Listener", 1899));
    }




    //@Test
    public void testInterruptsOfDatagramChannel() {
        final Data data = new Data();


        Runnable client = new Runnable() {
            @Override
            public void run() {
                // get ready to send our message
                DatagramChannel chan = null;
                try {
                    chan = DatagramChannel.open();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                CharBuffer c = CharBuffer.wrap("how are you?"); // already flipped ready to read out
                Charset utf8 = Charset.forName("utf-8");
                ByteBuffer encd = utf8.encode(c); // already flipped ready to read out

                // wait for server to broadcast its port
                while(data.serverPort == -1) {
                    System.out.println("client waiting");
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                // now send to server and await response
                System.out.println("client sending");
                try {
                    InetAddress addr = InetAddress.getLoopbackAddress();
                    chan.send(encd, new InetSocketAddress(addr, data.serverPort)); // read out of encd buf to send
                } catch (IOException e) {
                    e.printStackTrace();
                }
                ByteBuffer bufIn = ByteBuffer.allocate(200); // ready for writing
                System.out.println("client awaiting resp");
                try {
                    chan.receive(bufIn); // write into it
                } catch (IOException e) {
                    e.printStackTrace();
                }
                bufIn.flip(); // so we can read out
                CharBuffer chars = utf8.decode(bufIn); // read out of it
                System.out.println("<<< client heard: " + chars.toString());

                // now convey that client is finished
                data.state = "done";
                System.out.println("client exiting");
            }
        };

        Runnable terminator = new Runnable() {

            @Override
            public void run() {
                // wait until server state = 'got it'
                while (!data.state.equals("got it")) {
                    System.out.println("terminator: waiting");
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                System.out.println("terminator: interrupting listener");
                data.listenerTerminated = true;
                while (data.responders.size() > 0) {
                    System.out.println("terminator: waiting for responders");
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                System.out.println("terminator exiting");
            }
        };

        final Runnable responder = new Runnable() {

            @Override
            public void run() {
                Charset utf8 = Charset.forName("utf-8");
                CharBuffer chars = utf8.decode(data.serverBuf);
                System.out.println(">>> responder received: " + chars.toString());
                // signal to terminator that we got the message
                data.state = "got it";

                // now wait until listener sets state to 'terminated'
                while(! data.state.equals("terminated")) {
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                // now try and send response with the closed channel and see what happens
                chars = CharBuffer.wrap("Fine thanks"); // already flipped ready to read out
                ByteBuffer resp = utf8.encode(chars); // already flipped ready to read out
                try {
                    data.serverChan.send(resp, data.clientAddr); // read out of it
                } catch (IOException e) {
                    e.printStackTrace();
                }
                System.out.println("responder exiting");
            }
        };

        Runnable listener = new Runnable() {

            @Override
            public void run() {
                try {
                    data.serverChan = DatagramChannel.open();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    data.serverChan.socket().bind(null);
                } catch (SocketException e) {
                    e.printStackTrace();
                }
                data.serverPort = data.serverChan.socket().getLocalPort();
                SocketAddress addr = null;

                while (! data.listenerTerminated) {
                    data.serverBuf = ByteBuffer.allocate(200); // ready for writing into
                    System.out.println("listener awaiting req");
                    try {
                        data.clientAddr = data.serverChan.receive(data.serverBuf); // write into it
                        System.out.println("listener recevd req, launching responder");
                        data.serverBuf.flip(); // so responder can read back out

                        ////// launch responder here
                        Thread r = new Thread(responder);
                        data.responders.add(r);
                        r.start();
                    } catch (ClosedByInterruptException c) {
                        // signal to responder that the listener is terminated/channel is closed
                        System.out.println("listener terminated");
                        data.state = "terminated";
                        data.listenerTerminated = true;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                System.out.println("listener exiting");
            }
        };

        new Thread(client).start();
        new Thread(terminator).start();
        new Thread(listener).start();

        while(! data.state.equals("done")) {
            System.out.println("main waiting");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        System.out.println("main exiting");
    }
}
