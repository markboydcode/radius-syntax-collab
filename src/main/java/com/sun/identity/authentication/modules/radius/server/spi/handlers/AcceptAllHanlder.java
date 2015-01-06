package com.sun.identity.authentication.modules.radius.server.spi.handlers;

import com.sun.identity.authentication.modules.radius.client.AccessAccept;
import com.sun.identity.authentication.modules.radius.client.AccessRequest;
import com.sun.identity.authentication.modules.radius.server.RadiusResponseHandler;
import com.sun.identity.authentication.modules.radius.server.spi.AccessRequestHandler;

import java.util.Properties;

/**
 * Simple handler that sends a an AccessAccept for all incoming Radius access requests. This handler can be used to
 * test the connection from the Radius client to OpenAM without engaging the open am infrastructure when troubleshooting.
 *
 * Created by markboyd on 11/21/14.
 */
public class AcceptAllHanlder implements AccessRequestHandler {

    @Override
    public void init(Properties config) {
    }

    @Override
    public void handle(AccessRequest request, RadiusResponseHandler respHandler) {
        AccessAccept resp = new AccessAccept();
        respHandler.send(resp);
    }

    /**
     * Doesn't have any items to be purged at shutdown so it returns a null value.
     *
     * @return
     */
    @Override
    public ShutdownListener getShutdownListener() {
        return null;
    }
}
