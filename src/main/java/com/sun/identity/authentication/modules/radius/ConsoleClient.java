/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015 LDS
 */
package com.sun.identity.authentication.modules.radius;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.SecureRandom;
import java.util.Properties;

import com.sun.identity.authentication.modules.radius.client.AccessAccept;
import com.sun.identity.authentication.modules.radius.client.AccessChallenge;
import com.sun.identity.authentication.modules.radius.client.AccessReject;
import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.client.Attribute;
import com.sun.identity.authentication.modules.radius.client.AttributeSet;
import com.sun.identity.authentication.modules.radius.client.NASIPAddressAttribute;
import com.sun.identity.authentication.modules.radius.client.NASPortAttribute;
import com.sun.identity.authentication.modules.radius.client.Packet;
import com.sun.identity.authentication.modules.radius.client.PacketFactory;
import com.sun.identity.authentication.modules.radius.client.ReplyMessageAttribute;
import com.sun.identity.authentication.modules.radius.client.RequestAuthenticator;
import com.sun.identity.authentication.modules.radius.client.StateAttribute;
import com.sun.identity.authentication.modules.radius.client.UserNameAttribute;
import com.sun.identity.authentication.modules.radius.client.UserPasswordAttribute;
import com.sun.identity.authentication.modules.radius.server.RadiusRequestContext;
import com.sun.identity.authentication.modules.radius.server.config.RadiusServiceStarter;

/**
 * Implements a console based RADIUS client that enables testing of a radius server. Looks for a radius.properties in
 * the current directory and if not found indicates it is missing and what keys and values are needed to run then asks
 * for username and password to start the authentication process and presents access-accept as a SUCCESS output and
 * access-reject as a FAILURE output before exiting. For access-challenge responses it presents the message field and
 * prompts for answer. Following the submitted value it issues a new access-request including the answer in the password
 * field and returning any state field that was in the original access-challenge response. Created by markboyd on
 * 12/2/14.
 */
public class ConsoleClient implements Runnable {
    public static final String CONFIG_FILE = "radius.properties";

    public static final String HOST_PROP = "host";
    public static final String PORT_PROP = "port";
    public static final String SECRET_PROP = "secret";
    public static final String LOG_TRAFFIC_PROP = "show-traffic";

    private int port = -1;
    private String host = null;
    private String secret = null;
    private boolean logTraffic = false;

    public ConsoleClient(Properties props) {
        if (!props.containsKey(SECRET_PROP) || !props.containsKey(PORT_PROP) || !props.containsKey(HOST_PROP)) {
            usage();
        }
        this.secret = props.getProperty(SECRET_PROP);
        this.host = props.getProperty(HOST_PROP);
        this.port = Integer.parseInt(props.getProperty(PORT_PROP));
        this.logTraffic = Boolean.parseBoolean(props.getProperty(LOG_TRAFFIC_PROP));
    }

    private static void usage() {
        System.out.println("Missing required config file '" + CONFIG_FILE + "' in current directory "
                + new File("./").getAbsolutePath());
        System.out.println("Must Contain: ");
        System.out.println(" secret=<shared-secret-with-server>");
        System.out.println(" host=<hostname-or-ip-address>");
        System.out.println(" port=<port-on-target-host>");
        System.out.println();
        System.out.println("May Contain:");
        System.out.println(" show-traffic=true");
        System.exit(1);
    }

    public static void main(String[] args) throws IOException {
        RadiusServiceStarter.getInstance(); // just references the starter to force build version to show on command
                                            // line
        File cfg = new File("./" + CONFIG_FILE);

        if (!cfg.exists() || !cfg.isFile()) {
            usage();
        }

        Properties props = new Properties();
        props.load(new FileReader(cfg));

        ConsoleClient client = new ConsoleClient(props);
        client.run();
    }

    private String getUserInputFor(String label, String message) throws IOException {
        if (message != null) {
            System.out.println("---> " + message);
        }
        System.out.print("? " + label + ": ");
        System.out.flush();
        return new BufferedReader(new InputStreamReader(System.in)).readLine();
    }

    @Override
    public void run() {

        try {
            DatagramChannel chan = DatagramChannel.open();
            short reqId = 1; // request id
            SecureRandom random = new SecureRandom();
            InetSocketAddress serverAddr = new InetSocketAddress(this.host, this.port);
            NASIPAddressAttribute nasAddr = new NASIPAddressAttribute(InetAddress.getLocalHost());
            NASPortAttribute nasPort = new NASPortAttribute(chan.socket().getLocalPort());
            StateAttribute state = null;

            // String username = "boydmr"; // TODO: restore
            String username = getUserInputFor("Username", null);
            // String passwordOrAnswer = "password"; // TODO: restore
            String passwordOrAnswer = getUserInputFor("Password", null);
            System.out.println();

            boolean finished = false;
            ByteBuffer bufIn = ByteBuffer.allocate(4096); // ready for writing

            while (!finished) {
                RequestAuthenticator reqAuthR = new RequestAuthenticator(random, this.secret);
                AccessRequest req = new AccessRequest(reqId++, reqAuthR);
                req.addAttribute(new UserNameAttribute(username));
                req.addAttribute(new UserPasswordAttribute(req.getAuthenticator(), this.secret, passwordOrAnswer));
                req.addAttribute(nasAddr);
                req.addAttribute(nasPort);
                if (state != null) {
                    req.addAttribute(state);
                }
                ByteBuffer reqBuf = ByteBuffer.wrap(req.getData());

                if (logTraffic) {
                    System.out.println("Packet To " + host + ":" + port);
                    System.out.println(RadiusRequestContext.getPacketRepresentation(req));
                }
                chan.send(reqBuf, serverAddr);

                // now handle responses possibly sending additional requests
                chan.receive(bufIn);
                bufIn.flip(); // prepare buffer for reading out
                Packet res = PacketFactory.toPacket(bufIn);
                bufIn.clear(); // prepare buffer for next response

                if (logTraffic) {
                    System.out.println("Packet From " + host + ":" + port);
                    System.out.println(RadiusRequestContext.getPacketRepresentation(res));
                }
                if (res instanceof AccessReject) {
                    System.out.println("---> Sorry. Not Authenticated.");
                    System.out.println();
                    finished = true;
                } else if (res instanceof AccessAccept) {
                    System.out.println("---> SUCCESS! You've Authenticated!");
                    System.out.println();
                    finished = true;
                } else if (res instanceof AccessChallenge) {
                    AccessChallenge chng = (AccessChallenge) res;
                    state = (StateAttribute) getAttribute(StateAttribute.class, res);
                    ReplyMessageAttribute msg = (ReplyMessageAttribute) getAttribute(ReplyMessageAttribute.class, res);
                    String message = null;

                    if (msg != null) {
                        message = msg.getString();
                    }
                    passwordOrAnswer = getUserInputFor("Answer", message);
                    System.out.println();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Attribute getAttribute(Class clazz, Packet res) {
        AttributeSet atts = res.getAttributeSet();

        for (int i = 0; i < atts.size(); i++) {
            Attribute att = atts.getAttributeAt(i);
            if (att.getClass() == clazz) {
                return att;
            }
        }
        return null;
    }
}
