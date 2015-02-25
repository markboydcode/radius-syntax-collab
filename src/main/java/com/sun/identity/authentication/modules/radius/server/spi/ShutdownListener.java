package com.sun.identity.authentication.modules.radius.server.spi;

/**
 * An optional object handed back from an implementation of AccessRequestHandler if that implementation desires to be
 * notified when the server is shutting down. Only a single instance of this object will be obtained from the first
 * instantiated instance of the AccessRequestHandler implementor and delegated to when the server is shutting down.
 *
 * Created by markboyd on 12/12/14.
 */
public interface ShutdownListener {

    /**
     * Should terminate any resources necessary during shutdown and only return once they have exited or discarded.
     */
    public void terminate();
}
