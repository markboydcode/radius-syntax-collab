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
package com.sun.identity.authentication.modules.radius.server.poc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.sun.identity.authentication.modules.radius.client.AccessAccept;
import com.sun.identity.authentication.modules.radius.client.AccessChallenge;
import com.sun.identity.authentication.modules.radius.client.AccessReject;
import com.sun.identity.authentication.modules.radius.client.Attribute;
import com.sun.identity.authentication.modules.radius.client.AttributeSet;
import com.sun.identity.authentication.modules.radius.client.Packet;
import com.sun.identity.authentication.modules.radius.client.ReplyMessageAttribute;
import com.sun.identity.authentication.modules.radius.client.ResponseAuthenticator;
import com.sun.identity.authentication.modules.radius.client.StateAttribute;

/**
 * Builder of processors that transmit RADIUS responses to the connected client. Created by markboyd on 6/30/14.
 */
public class Send {

    /**
     * Creates a processor that sends a RADIUS Accept-Challenge response to the client including the current state's
     * message.
     *
     * @return
     */
    public static TransitionProcessor radiusChallenge() {
        return new TransitionProcessor() {
            @Override
            public void process(RequestInfo req, Context ctx, String message) {
                Packet response = new AccessChallenge();
                String s = message;

                while (s.length() > 0) {
                    ReplyMessageAttribute att = new ReplyMessageAttribute(s);
                    response.addAttribute(att);
                    String consumed = att.getString();
                    s = s.substring(consumed.length());
                }
                response.addAttribute(new StateAttribute(req.stateHolder.toRadiusValue()));
                response.setIdentifier(req.pkt.getIdentifier());
                injectResponseAuthenticator(response, req);

                // and send it off
                byte[] onTheWireFormat = response.getData();
                System.out.println("<---- " + response.getType() + " - " + req.pkt.getIdentifier() + " for "
                        + req.username);
                dumpAttributesToStdOut(response);

                try {
                    ctx.channel.send(ByteBuffer.wrap(onTheWireFormat), req.addr);
                } catch (IOException e) {
                    System.out.println("Unable to send response packet");
                    e.printStackTrace();
                }
                System.out
                        .println("   -- DONE : "
                                + ctx.ELAPSED_SECONDS_FORMATTER.format((System.currentTimeMillis() - req.start))
                                + "ms elapsed");
                System.out.println();

            }
        };
    }

    /**
     * Replace this at some point. Dumps attributes to standard out in raw hex and read-able chars (where possible)
     * 
     * @param pkt
     */
    public static void dumpAttributesToStdOut(Packet pkt) {
        AttributeSet atts = pkt.getAttributeSet();
        for (int i = 0; i < atts.size(); i++) {
            Attribute a = atts.getAttributeAt(i);
            System.out.println("    - " + a);
        }
        System.out.println();
    }

    /**
     * Crafts the response authenticator as per the Response Authenticator paragraph of section 3 of rfc 2865 and
     * injects into the response packet.
     *
     * @param response
     * @param reqInf
     */
    private static void injectResponseAuthenticator(Packet response, RequestInfo reqInf) {
        response.setAuthenticator(reqInf.pkt.getAuthenticator());
        byte[] onTheWireFormat = response.getData();

        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            // ignore. if happens let it die since this jvm is hosed
        }
        md5.update(onTheWireFormat);
        md5.update(reqInf.clientSecret.getBytes());
        byte[] hash = md5.digest();

        ResponseAuthenticator ra = new ResponseAuthenticator(hash);

        // now replace the req authnctr used for gen'ing the response authntctr
        response.setAuthenticator(ra);
    }

    public static TransitionProcessor radiusAccessAllowed() {
        return new TransitionProcessor() {
            @Override
            public void process(RequestInfo req, Context ctx, String message) {
                Packet response = new AccessAccept();
                response.setIdentifier(req.pkt.getIdentifier());
                injectResponseAuthenticator(response, req);

                // and send it off
                byte[] onTheWireFormat = response.getData();
                System.out.println("<---- " + response.getType() + " - " + req.pkt.getIdentifier() + " for "
                        + req.username);
                dumpAttributesToStdOut(response);

                try {
                    ctx.channel.send(ByteBuffer.wrap(onTheWireFormat), req.addr);
                } catch (IOException e) {
                    System.out.println("Unable to send response packet");
                    e.printStackTrace();
                }
                System.out
                        .println("   -- DONE : "
                                + ctx.ELAPSED_SECONDS_FORMATTER.format((System.currentTimeMillis() - req.start))
                                + "ms elapsed");
                System.out.println();

            }
        };
    }

    public static TransitionProcessor radiusAccessReject(final String reason) {
        return new TransitionProcessor() {
            @Override
            public void process(RequestInfo req, Context ctx, String message) {
                Packet response = new AccessReject();
                ReplyMessageAttribute att = new ReplyMessageAttribute(reason);
                response.addAttribute(att);

                response.setIdentifier(req.pkt.getIdentifier());
                injectResponseAuthenticator(response, req);

                // and send it off
                byte[] onTheWireFormat = response.getData();
                System.out.println("<---- " + response.getType() + " - " + req.pkt.getIdentifier() + " for "
                        + req.username);
                dumpAttributesToStdOut(response);

                try {
                    ctx.channel.send(ByteBuffer.wrap(onTheWireFormat), req.addr);
                } catch (IOException e) {
                    System.out.println("Unable to send response packet");
                    e.printStackTrace();
                }
                System.out
                        .println("   -- DONE : "
                                + ctx.ELAPSED_SECONDS_FORMATTER.format((System.currentTimeMillis() - req.start))
                                + "ms elapsed");
                System.out.println();
            }
        };
    }
}
