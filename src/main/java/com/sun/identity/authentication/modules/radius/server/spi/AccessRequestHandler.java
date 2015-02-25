package com.sun.identity.authentication.modules.radius.server.spi;

import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.server.RadiusResponseHandler;

import java.util.Properties;

/**
 * Defines the interface for handlers of incoming Access-Request packets.
 *
 * Created by markboyd on 11/21/14.
 */
public interface AccessRequestHandler {

    /**
     * Passes to the handler configuration parameters declared in OpenAM's admin console for the client's declared
     * handler class.
     *  @param config
     *
     */
    public void init(Properties config);

    /**
     * Determines how the passed-in request should be handled and calls the send method in the context passing the
     * appropriate response packet of type AccessAccept, AccessReject, or AccessChallenge. Only
     * one call to the context's send method is accepted. Any following calls will be ignored. Once this method returns,
     * the context object is disabled so that any subsequent calls by a launched thread for example will be ignored.
     * If this method returns without invoking the handler's send method then the request packet is essentially
     * dropped silently.
     *
     * @param request
     * @param context
     * @return
     */
    public void handle(AccessRequest request, RadiusResponseHandler context);

    /**
     * Returns an instance of ShutdownListener if this class uses constructs that should be purged when the server is
     * shutting down or null if no shutdown call is needed. Will only be called on the first instance instantiated of
     * the implementor of this interface and if non-null, the returned instance will be registered and called during
     * ContextListerner shutdown. An example of such a resource is creation of a threadpool or launching of a thread
     * to periodically clear a cache.
     *
     * @return
     */
    public ShutdownListener getShutdownListener();
}
