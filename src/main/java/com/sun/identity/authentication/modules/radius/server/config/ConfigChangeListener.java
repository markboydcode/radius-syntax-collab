package com.sun.identity.authentication.modules.radius.server.config;

import com.sun.identity.sm.ServiceListener;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by markboyd on 11/11/14.
 */
public class ConfigChangeListener implements ServiceListener {
    private static final Logger cLog = Logger.getLogger(ConfigChangeListener.class.getName());

    /**
     * Blocking queue used to communicate with RuntimeServiceController that handlerConfig changes were made and the service
     * should restart or adjust accordingly.
     */
    private final ArrayBlockingQueue<String> configChangedQueue;


    public ConfigChangeListener(ArrayBlockingQueue<String> configChangedQueue) {
        this.configChangedQueue = configChangedQueue;
    }

    @Override
    public void schemaChanged(String serviceName, String version) {
        // ignore for now.
    }

    @Override
    public void globalConfigChanged(String serviceName, String version, String groupName, String serviceComponent, int type) {
        boolean accepted = configChangedQueue.offer("RADIUS Config Changed. Loading...");

        if (! accepted) {
            cLog.log(Level.INFO, "RADIUS Client handlerConfig changed but change queue is full. Only happens when previous " +
                    "change event takes too long to load changes. Existing queued events will force loading of these changes. " +
                    "Therefore, dropping event.");
        }
    }

    @Override
    public void organizationConfigChanged(String serviceName, String version, String orgName, String groupName, String serviceComponent, int type) {
        // ignore since we don't have any explicit realm related data in our handlerConfig
    }
}
