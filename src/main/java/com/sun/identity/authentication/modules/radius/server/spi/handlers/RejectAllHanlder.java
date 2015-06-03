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
package com.sun.identity.authentication.modules.radius.server.spi.handlers;

import java.util.Properties;

import com.sun.identity.authentication.modules.radius.client.AccessReject;
import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.server.RadiusResponseHandler;
import com.sun.identity.authentication.modules.radius.server.spi.AccessRequestHandler;
import com.sun.identity.authentication.modules.radius.server.spi.ShutdownListener;

/**
 * Simple handler that sends a an AccessReject for all incoming Radius access requests. This handler can be used to test
 * the connection from the Radius client to OpenAM without engaging the open am infrastructure when troubleshooting.
 * Created by markboyd on 11/21/14.
 */
public class RejectAllHanlder implements AccessRequestHandler {

    @Override
    public void init(Properties config) {
    }

    @Override
    public void handle(AccessRequest request, RadiusResponseHandler respHandler) {
        AccessReject resp = new AccessReject();
        respHandler.send(resp);
    }

    /**
     * Doesn't have any items to be purged at shutdown so it returns a null value.
     *
     * @return a null ShutdownListener reference.
     */
    @Override
    public ShutdownListener getShutdownListener() {
        return null;
    }
}
