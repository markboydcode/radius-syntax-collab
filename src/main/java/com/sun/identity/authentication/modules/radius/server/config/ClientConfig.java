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
     * The declared classname for the client. This is what is declared for the client and does not indicated whether or
     * not the class is found.
     */
    public String classname;
    /**
     * The class declared for this client to handle requests and that implements the AccessRequestHandler interface. May
     * be null if the class declared for the client was not found by the classloader.
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
