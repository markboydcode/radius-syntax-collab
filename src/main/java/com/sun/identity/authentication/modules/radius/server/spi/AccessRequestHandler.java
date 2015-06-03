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
package com.sun.identity.authentication.modules.radius.server.spi;

import java.util.Properties;

import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.server.RadiusResponseHandler;

/**
 * Defines the interface for handlers of incoming Access-Request packets. Created by markboyd on 11/21/14.
 */
public interface AccessRequestHandler {

    /**
     * Passes to the handler configuration parameters declared in OpenAM's admin console for the client's declared
     * handler class.
     *
     * @param config
     *            - the handler configuration parameters.
     */
    public void init(Properties config);

    /**
     * Determines how the passed-in request should be handled and calls the send method in the context passing the
     * appropriate response packet of type AccessAccept, AccessReject, or AccessChallenge. Only one call to the
     * context's send method is accepted. Any following calls will be ignored. Once this method returns, the context
     * object is disabled so that any subsequent calls by a launched thread for example will be ignored. If this method
     * returns without invoking the handler's send method then the request packet is essentially dropped silently.
     *
     * @param request
     *            the access request
     * @param context
     *            the context in which the request is being made.
     * @return
     */
    public void handle(AccessRequest request, RadiusResponseHandler context);

    /**
     * Returns an instance of ShutdownListener if this class uses constructs that should be purged when the server is
     * shutting down or null if no shutdown call is needed. Will only be called on the first instance instantiated of
     * the implementor of this interface and if non-null, the returned instance will be registered and called during
     * ContextListerner shutdown. An example of such a resource is creation of a threadpool or launching of a thread to
     * periodically clear a cache.
     *
     * @return the shutdown listener or null if no shutdown call is needed.
     */
    public ShutdownListener getShutdownListener();
}
