package com.sun.identity.authentication.modules.radius.server.config;

import java.util.Properties;

/**
 * Holds information for a RADIUS client that is allowed to connect to this RADIUS server to perform authentication.
 * Created by markboyd on 11/11/14.
 */
public class ClientConfig {
    /**
     * The name of the client used solely for associating configuration and log messages with a given NAS server.
     */
    public String name;

    /**
     * The IP address from which incoming packets must be to be associated with this client.
     */
    public String ipaddr;

    /**
     * The shared secret used by both client and server for encryption and decryption and signing of the packets.
     */
    public String secret;

    /**
     * The declared classname for the client. This is what is declared for the client and does not indicated whether
     * or not the class is found.
     */
    public String classname;
    /**
     * The class declared for this client to handle requests and that implements the AccessRequestHandler interface.
     * May be null if the class declared for the client was not found by the classloader.
     */
    public Class clazz;

    /**
     * Indicates if the classname specified for the client was load-able and implemented the proper interface.
     */
    public boolean classIsValid;

    /**
     * The set of declared properties to be passed to the declared handler class immediately after instantiation and
     * before handling.
     */
    public Properties handlerConfig;

    /**
     * Indicates if packet contents for this client should be dumped to log for troubleshooting.
     */
    public boolean logPackets = false;
}
