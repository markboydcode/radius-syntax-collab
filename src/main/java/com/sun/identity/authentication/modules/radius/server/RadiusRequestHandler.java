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

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.client.AccessReject;
import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.client.Packet;
import com.sun.identity.authentication.modules.radius.client.PacketFactory;
import com.sun.identity.authentication.modules.radius.server.spi.AccessRequestHandler;

/**
 * Handles valid (ie: from approved clients) incoming radius access-request packets passing responsibility for
 * generating a response to the client's declared handler class. Created by markboyd on 11/13/14.
 */
public class RadiusRequestHandler implements Runnable {
    private static final Logger cLog = Logger.getLogger(RadiusRequestHandler.class.getName());

    /**
     * Buffer containing the on-the-wire bytes of the request prior to parsing.
     */
    private final ByteBuffer buffer;

    /**
     * The ResponseContext object providing access to client handlerConfig, receiving channel, and remote user identity.
     */
    private final RadiusRequestContext reqCtx;

    /**
     * The pojo representing the radius access-request parsed from the received buffer content.
     */
    private Packet request = null;

    /**
     * Instantiate a handler.
     * 
     * @param reqCtx
     * @param buffer
     */
    public RadiusRequestHandler(RadiusRequestContext reqCtx, ByteBuffer buffer) {
        this.reqCtx = reqCtx;
        this.buffer = buffer;
    }

    /**
     * Returns the name of the client from which the packet was received.
     * 
     * @return
     */
    public String getClientName() {
        return reqCtx.clientConfig.name;
    }

    @Override
    public void run() {
        try {
            // parse into a packet object
            try {
                request = PacketFactory.toPacket(buffer);
            } catch (Exception e) {
                cLog.log(Level.SEVERE, "Unable to parse packet received from RADIUS client '" + getClientName()
                        + "'. Dropping.", e);
                return;
            }

            // log packet if client handlerConfig indicates
            if (reqCtx.clientConfig.logPackets) {
                /*
                 * Code for forcing userpassword field to decrypt the password and in conjuntion with commented out
                 * version of toStringImpl in that class causing the password to be logged in the clear within the
                 * packet traffic when debugging encryption issue that is now resolved. This code should remain
                 * commented out when running in a production environment.
                 */
                /*
                 * AttributeSet atts = request.getAttributeSet(); for (int i = 0; i < atts.size(); i++) { Attribute a =
                 * atts.getAttributeAt(i); if (a.getType() == AttributeType.USER_PASSWORD.getTypeCode()) {
                 * UserPasswordAttribute upa = (UserPasswordAttribute) a;
                 * upa.extractPassword(request.getAuthenticator(), reqCtx.clientConfig.secret); } }
                 */
                reqCtx.logPacketContent(request, "\nPacket from " + getClientName() + ":");
            }

            // verify packet type
            if (request.getType() != PacketType.ACCESS_REQUEST) {
                cLog.log(Level.SEVERE, "Received non Access-Request packet from RADIUS client '" + getClientName()
                        + "'. Dropping.");
                return;
            }

            // grab the items from the request that we'll need in the RadiusResponseHandler at send time
            reqCtx.requestId = request.getIdentifier();
            reqCtx.requestAuthenticator = request.getAuthenticator();

            AccessRequest accessRequest = null;
            try {
                accessRequest = (AccessRequest) this.request;
            } catch (ClassCastException c) {
                // should never happen
                cLog.log(Level.SEVERE, "Received packet of type ACCESS_REQUEST from RADIUS client '"
                        + reqCtx.clientConfig.name + "' but unable to cast to AccessRequest. Rejecting access.", c);
                reqCtx.send(new AccessReject());
                return;
            }

            // instantiate declared handler, initialize, and pass it control
            AccessRequestHandler handler = null;
            try {
                handler = (AccessRequestHandler) reqCtx.clientConfig.clazz.newInstance();
            } catch (Exception e) {
                cLog.log(Level.SEVERE,
                        "Unable to instantiate declared handler class '" + reqCtx.clientConfig.clazz.getName()
                                + "' for RADIUS client '" + reqCtx.clientConfig.name + "'. Rejecting access.", e);
                reqCtx.send(new AccessReject());
                return;
            }
            try {
                handler.init(reqCtx.clientConfig.handlerConfig);
            } catch (Throwable t) {
                cLog.log(Level.SEVERE,
                        "Unable to initialize declared handler class '" + reqCtx.clientConfig.clazz.getName()
                                + "' for RADIUS client '" + reqCtx.clientConfig.name + "'. Rejecting access.", t);
                reqCtx.send(new AccessReject());
                return;
            }
            RadiusResponseHandler receiver = new RadiusResponseHandler(reqCtx);
            try {
                handler.handle(accessRequest, receiver);
            } catch (Throwable t) {
                cLog.log(Level.SEVERE, "Exception occured in handle() method of handler class '"
                        + reqCtx.clientConfig.clazz.getName() + "' for RADIUS client '" + reqCtx.clientConfig.name
                        + "'. Rejecting access.", t);
                reqCtx.send(new AccessReject());
                return;
            }

            if (!reqCtx.sendWasCalled) {
                cLog.log(Level.SEVERE, "Handler class '" + reqCtx.clientConfig.clazz.getSimpleName()
                        + "' declared for RADIUS client '" + reqCtx.clientConfig.name
                        + "' did not send response. Rejecting access.");
                reqCtx.send(new AccessReject());
            }

        } catch (Throwable t) {
            cLog.log(Level.SEVERE, "Runtime Exception occurred during RADIUS handling. Rejecting access.", t);
            reqCtx.send(new AccessReject());
            return;
        }
    }
}
