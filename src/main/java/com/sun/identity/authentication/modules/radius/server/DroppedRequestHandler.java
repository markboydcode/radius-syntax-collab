package com.sun.identity.authentication.modules.radius.server;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles requests when the thread pool's queue is full.
 *
 * Created by markboyd on 11/13/14.
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
