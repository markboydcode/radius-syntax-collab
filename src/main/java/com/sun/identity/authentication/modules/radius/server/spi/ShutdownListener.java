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

/**
 * An optional object handed back from an implementation of AccessRequestHandler if that implementation desires to be
 * notified when the server is shutting down. Only a single instance of this object will be obtained from the first
 * instantiated instance of the AccessRequestHandler implementor and delegated to when the server is shutting down.
 * Created by markboyd on 12/12/14.
 */
public interface ShutdownListener {

    /**
     * Should terminate any resources necessary during shutdown and only return once they have exited or discarded.
     */
    public void terminate();
}
