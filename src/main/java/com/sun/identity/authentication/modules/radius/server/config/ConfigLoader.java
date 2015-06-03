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

//import com.iplanet.sso.SSOToken;

import java.security.AccessController;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.modules.radius.server.spi.AccessRequestHandler;
import com.sun.identity.authentication.modules.radius.server.spi.ShutdownListener;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

//import com.sun.identity.security.AdminTokenAction;
//import com.sun.identity.sm.ServiceConfig;
//import com.sun.identity.sm.ServiceConfigManager;
//
//import java.security.AccessController;

/**
 * Loads configuration values from openam's admin console maintained values into pojos and registers a change listener
 * for changes that may happen in the future . Created by markboyd on 11/12/14.
 */
public class ConfigLoader {
    private static final Logger cLog = Logger.getLogger(ConfigLoader.class.getName());

    /**
     * The ID of the listener in case we ever need to unregister it. If it is null then we haven't yet installed our
     * listener for admin console handlerConfig changes to our constructs.
     */
    private String listenerId = null;

    /**
     * Registry of shutdown listeners if any provided by the classes implementing AccessRequestHandler. Only on instance
     * per class is registered.
     */
    private Map<Class, ShutdownListener> shutdownListeners = new HashMap<Class, ShutdownListener>();

    /**
     * Loads the configured global RADIUS Service values and declared clients as specified in openAM's admin console via
     * registration of those properties via the amRadiusServer.xml file. We load them here into simple pojos for caching
     * in memory. If we are unable to do so this method will return a null value.
     *
     * @return
     * @param configChangedQueue
     */
    public RadiusServiceConfig loadConfig(ArrayBlockingQueue<String> configChangedQueue) {
        try {
            // get a ServiceConfigManager for our service
            SSOToken admTk = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());
            ServiceConfigManager mgr = new ServiceConfigManager(Constants.RADIUS_SERVICE_NAME, admTk);

            if (mgr != null) {
                // toss in our listener if we haven't registered yet
                if (listenerId == null) {
                    this.listenerId = mgr.addListener(new ConfigChangeListener(configChangedQueue));
                }
                // now get the fields in the Configuration tab, Global sub-tab, Global Properties table, RADIUS client
                // page
                RadiusServiceConfig cfg = null;
                ServiceConfig serviceConf = mgr.getGlobalConfig("default");

                if (serviceConf != null) {
                    List<ClientConfig> definedClientConfigs = new ArrayList<ClientConfig>();
                    boolean isEnabled = false;
                    int listenerPort = -1;
                    Map<String, Set<String>> map = serviceConf.getAttributes();
                    int coreThreads = -1;
                    int maxThreads = -1;
                    int queueSize = -1;
                    int keepaliveSeconds = -1;

                    for (Map.Entry<String, Set<String>> ent : map.entrySet()) {
                        String key = ent.getKey();
                        String value = extractValue(ent.getValue());
                        if (Constants.GBL_ATT_LISTENER_ENABLED.equals(key)) {
                            isEnabled = "YES".equals(value);
                        }
                        // in the lines below we don't need to catch NumberFormatException due to limiting values in
                        // the xml file which is enforced by admin console editing
                        else if (Constants.GBL_ATT_LISTENER_PORT.equals(key)) {
                            listenerPort = Integer.parseInt(value);
                        } else if (Constants.GBL_ATT_THREADS_CORE_SIZE.equals(key)) {
                            coreThreads = Integer.parseInt(value);
                        } else if (Constants.GBL_ATT_THREADS_MAX_SIZE.equals(key)) {
                            maxThreads = Integer.parseInt(value);
                        } else if (Constants.GBL_ATT_QUEUE_SIZE.equals(key)) {
                            queueSize = Integer.parseInt(value);
                        } else if (Constants.GBL_ATT_THREADS_KEEPALIVE_SECONDS.equals(key)) {
                            keepaliveSeconds = Integer.parseInt(value);
                        }
                    }
                    ThreadPoolConfig poolCfg = new ThreadPoolConfig(coreThreads, maxThreads, queueSize,
                            keepaliveSeconds);

                    // now get the RADIUS client instances from the secondary configuration instances table in the
                    // Configuration tab, Global sub-tab, Global Properties table, RADIUS client page
                    Set<String> names = serviceConf.getSubConfigNames();

                    for (String s : names) {
                        ClientConfig clientConfig = new ClientConfig(); // create object for holding values in memory
                        clientConfig.name = s;
                        ServiceConfig clientCfg = serviceConf.getSubConfig(s); // go get our admin console values
                        map = clientCfg.getAttributes();

                        // now just like above we pull out the values by field name
                        for (Map.Entry<String, Set<String>> ent : map.entrySet()) {
                            String key = ent.getKey();

                            if (Constants.CLIENT_ATT_IP_ADDR.equals(key)) {
                                clientConfig.ipaddr = extractValue(ent.getValue());
                            } else if (Constants.CLIENT_ATT_SECRET.equals(key)) {
                                clientConfig.secret = extractValue(ent.getValue());
                            } else if (Constants.CLIENT_ATT_LOG_PACKETS.equals(key)) {
                                clientConfig.logPackets = "YES".equals(extractValue(ent.getValue()));
                            } else if (Constants.CLIENT_ATT_CLASSNAME.equals(key)) {
                                clientConfig.classname = extractValue(ent.getValue());
                                clientConfig.clazz = validateClass(clientConfig);
                                clientConfig.classIsValid = clientConfig.clazz != null;
                            } else if (Constants.CLIENT_ATT_PROPERTIES.equals(key)) {
                                clientConfig.handlerConfig = extractProperties(ent.getValue());
                            }
                        }
                        definedClientConfigs.add(clientConfig);
                    }
                    cfg = new RadiusServiceConfig(isEnabled, listenerPort, poolCfg,
                            definedClientConfigs.toArray(new ClientConfig[0]));
                }
                return cfg;
            } else {
                cLog.log(Level.SEVERE,
                        "Returned Configuration Manager Instance for RADIUS Service is null. Unable to load RADIUS Service configuration.");
            }
        } catch (Exception e) {
            cLog.log(Level.SEVERE, "Unable to load RADIUS Service Configuration", e);
        }
        return null;
    }

    /**
     * Validates that the specified class can be loaded and implements the proper interface so that we don't have to do
     * that for every request.
     *
     * @param cfg
     */
    private Class validateClass(ClientConfig cfg) {
        ClassLoader ldr = Thread.currentThread().getContextClassLoader();
        Class clazz = null;
        try {
            clazz = ldr.loadClass(cfg.classname);
        } catch (ClassNotFoundException e) {
            cLog.log(Level.SEVERE, "Unable to load Handler Class '" + cfg.classname + "' for RADIUS client '"
                    + cfg.name + "'. Requests from this client will be ignored.", e);
            return null;
        }
        Object inst = null;

        try {
            inst = clazz.newInstance();
        } catch (InstantiationException e) {
            cLog.log(Level.SEVERE, "Unable to instantiate Handler Class '" + cfg.classname + "' for RADIUS client '"
                    + cfg.name + "'. Requests from this client will be ignored.", e);
            return null;
        } catch (IllegalAccessException e) {
            cLog.log(Level.SEVERE, "Unable to access Handler Class '" + cfg.classname + "' for RADIUS client '"
                    + cfg.name + "'. Requests from this client will be ignored.", e);
            return null;
        }
        AccessRequestHandler handler = null;
        try {
            handler = (AccessRequestHandler) inst;
        } catch (ClassCastException e) {
            cLog.log(Level.SEVERE, "Unable to use Handler Class '" + cfg.classname + "' for RADIUS client '" + cfg.name
                    + "'. Requests from this client will be ignored.", e);
            return null;
        }
        ShutdownListener listener = handler.getShutdownListener();

        if (listener != null) {
            if (!shutdownListeners.containsKey(clazz)) {
                shutdownListeners.put(clazz, listener);
            }
        }
        return clazz;
    }

    /**
     * Utility method to extract multiple values from the Set wrapper and place them in a java Properties object. Each
     * item is parsed as a key followed by an equals character followed by a value. If there is no equals sign then the
     * item is entered into a the properties object with an empty string value
     *
     * @param wrappingSet
     * @return
     */
    private Properties extractProperties(Set<String> wrappingSet) {
        String[] vals = wrappingSet.toArray(Constants.STRING_ARY);
        Properties cfg = new Properties();

        for (String val : vals) {
            int idx = val.indexOf('=');

            if (idx == -1) {
                cfg.setProperty(val, "");
            } else {
                cfg.setProperty(val.substring(0, idx), val.substring(idx + 1));
            }
        }
        return cfg;
    }

    /**
     * Notifies handler shutdown listeners if any that the server is shuting down and returns after all have returned
     * from their terminate method.
     */
    void notifyHandlerShutdownListeners() {
        for (ShutdownListener l : shutdownListeners.values()) {
            l.terminate();
        }
    }

    /**
     * Utility method to extract single values from the silly Set wrappers that all values have in openAM's admin
     * console handlerConfig system.
     * 
     * @param wrappingSet
     * @return
     */
    private String extractValue(Set<String> wrappingSet) {
        String[] vals = wrappingSet.toArray(Constants.STRING_ARY);
        return vals[0];
    }

}
