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
package com.sun.identity.authentication.modules.radius.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.client.Attribute;
import com.sun.identity.authentication.modules.radius.client.AttributeSet;
import com.sun.identity.authentication.modules.radius.client.NASIPAddressAttribute;
import com.sun.identity.authentication.modules.radius.client.NASPortAttribute;
import com.sun.identity.authentication.modules.radius.client.Packet;
import com.sun.identity.authentication.modules.radius.client.PacketFactory;
import com.sun.identity.authentication.modules.radius.client.RequestAuthenticator;
import com.sun.identity.authentication.modules.radius.client.StateAttribute;
import com.sun.identity.authentication.modules.radius.client.UserNameAttribute;
import com.sun.identity.authentication.modules.radius.client.UserPasswordAttribute;

/**
 * Created by markboyd on 11/21/14.
 */
public class TestOpenamWithGreetingHandler {

    private int serverPort = 1812;

    // @Test
    public void test() throws NoSuchAlgorithmException, IOException {
        DatagramChannel chan = DatagramChannel.open();
        short reqId = 1; // request id
        SecureRandom random = new SecureRandom();
        RequestAuthenticator reqAuthR = new RequestAuthenticator(random, "MY-SECRET");

        AccessRequest req = new AccessRequest(reqId, reqAuthR);
        req.addAttribute(new UserNameAttribute("test-user"));
        req.addAttribute(new UserPasswordAttribute(req.getAuthenticator(), "MY-SECRET", "password"));
        req.addAttribute(new NASIPAddressAttribute(InetAddress.getLocalHost()));
        req.addAttribute(new NASPortAttribute(1200));
        ByteBuffer reqBuf = ByteBuffer.wrap(req.getData());

        // now send to server and await response
        System.out.println("client sending");
        try {
            InetAddress addr = InetAddress.getLoopbackAddress();
            chan.send(reqBuf, new InetSocketAddress(addr, 1812));
        } catch (IOException e) {
            e.printStackTrace();
        }
        ByteBuffer bufIn = ByteBuffer.allocate(4096); // ready for writing
        System.out.println("client awaiting resp");
        try {
            chan.receive(bufIn); // write into it
        } catch (IOException e) {
            e.printStackTrace();
        }
        bufIn.flip(); // so we can read out
        Packet p = PacketFactory.toPacket(bufIn);
        StateAttribute state = null;

        if (p.getType() == PacketType.ACCESS_CHALLENGE) {
            System.out.println("received: ");
            AttributeSet atts = p.getAttributeSet();
            for (int i = 0; i < atts.size(); i++) {
                Attribute att = atts.getAttributeAt(i);
                System.out.println("  " + att.toString());
                if (att.getType() == AttributeType.STATE.getTypeCode()) {
                    state = (StateAttribute) att;
                }
            }
        }
        // now send the response back
        reqId++;
        AccessRequest req2 = new AccessRequest(reqId, reqAuthR);
        req2.addAttribute(new UserNameAttribute("test-user"));
        req2.addAttribute(new UserPasswordAttribute(req.getAuthenticator(), "MY-SECRET", "empty-answer"));
        req2.addAttribute(new NASIPAddressAttribute(InetAddress.getLocalHost()));
        req2.addAttribute(new NASPortAttribute(1200));
        req2.addAttribute(state);
        reqBuf = ByteBuffer.wrap(req2.getData());

        // now send to server and await response
        System.out.println("client sending");
        try {
            InetAddress addr = InetAddress.getLoopbackAddress();
            chan.send(reqBuf, new InetSocketAddress(addr, 1812));
        } catch (IOException e) {
            e.printStackTrace();
        }

        bufIn = ByteBuffer.allocate(4096); // ready for writing
        System.out.println("client awaiting resp");
        try {
            chan.receive(bufIn); // write into it
        } catch (IOException e) {
            e.printStackTrace();
        }
        bufIn.flip(); // so we can read out
        p = PacketFactory.toPacket(bufIn);

        if (p.getType() == PacketType.ACCESS_CHALLENGE) {
            System.out.println("received: ");
            AttributeSet atts = p.getAttributeSet();
            for (int i = 0; i < atts.size(); i++) {
                Attribute att = atts.getAttributeAt(i);
                System.out.println("  " + att.toString());
            }
        }

        chan.close();
        System.out.println("client exiting");
    }
}
