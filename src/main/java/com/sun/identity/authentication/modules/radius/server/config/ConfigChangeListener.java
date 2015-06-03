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

import java.util.concurrent.ArrayBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.identity.sm.ServiceListener;

/**
 * Created by markboyd on 11/11/14.
 */
public class ConfigChangeListener implements ServiceListener {
    private static final Logger cLog = Logger.getLogger(ConfigChangeListener.class.getName());

    /**
     * Blocking queue used to communicate with RuntimeServiceController that handlerConfig changes were made and the
     * service should restart or adjust accordingly.
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
    public void globalConfigChanged(String serviceName, String version, String groupName, String serviceComponent,
            int type) {
        boolean accepted = configChangedQueue.offer("RADIUS Config Changed. Loading...");

        if (!accepted) {
            cLog.log(
                    Level.INFO,
                    "RADIUS Client handlerConfig changed but change queue is full. Only happens when previous "
                            + "change event takes too long to load changes. Existing queued events will force loading of these changes. "
                            + "Therefore, dropping event.");
        }
    }

    @Override
    public void organizationConfigChanged(String serviceName, String version, String orgName, String groupName,
            String serviceComponent, int type) {
        // ignore since we don't have any explicit realm related data in our handlerConfig
    }
}
