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

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles requests when the thread pool's queue is full. Created by markboyd on 11/13/14.
 */
public class DroppedRequestHandler implements RejectedExecutionHandler {
    private static final Logger cLog = Logger.getLogger(DroppedRequestHandler.class.getName());

    /**
     * Called when request is added to the pool but its queue is full.
     *
     * @param r
     * @param executor
     */
    @Override
    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
        RadiusRequestHandler handler = (RadiusRequestHandler) r;
        cLog.log(Level.WARNING, "RADIUS thread pool queue full. Dropping packet from " + handler.getClientName());
    }
}
