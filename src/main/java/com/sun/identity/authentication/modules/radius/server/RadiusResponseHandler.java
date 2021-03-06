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
import java.util.logging.Logger;

import com.sun.identity.authentication.modules.radius.client.Packet;
import com.sun.identity.authentication.modules.radius.client.UserPasswordAttribute;

/**
 * Provides AccessRequestHandlers the means to send their response to a given request. Created by markboyd on 11/21/14.
 */
public class RadiusResponseHandler {
    private static final Logger cLog = Logger.getLogger(RadiusResponseHandler.class.getName());

    /**
     * The request context object providing access to the source address of the packet and feedback on the response
     * result.
     */
    private final RadiusRequestContext reqCtx;

    /**
     * Constructs a response handler instance.
     *
     * @param reqCtx
     */
    public RadiusResponseHandler(RadiusRequestContext reqCtx) {
        this.reqCtx = reqCtx;
    }

    /**
     * Takes the passed-in packet, injects the ID of the request and a response authenticator and sends it to the source
     * of the request.
     *
     * @param response
     */
    public void send(Packet response) {
        // delegate to the context object to do the work.
        reqCtx.send(response);
    }

    /**
     * Extracts the password from the provided UserPasswordAttribute object. This is done here since we have the request
     * context holding both the authenticator and secret which are needed to decrypt the attribute's contents.
     *
     * @param credAtt
     * @return
     */
    public String extractPassword(UserPasswordAttribute credAtt) throws IOException {
        return credAtt.extractPassword(reqCtx.requestAuthenticator, reqCtx.clientConfig.secret);
    }
}
