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

/**
 * Configuration values for the thread pool loaded from OpenAM's admin console constructs. Created by markboyd on
 * 11/13/14.
 */
public class ThreadPoolConfig {

    public final int keepAliveSeconds;
    public final int queueSize;
    public final int maxThreads;
    public final int coreThreads;

    public ThreadPoolConfig(int core, int max, int queueSize, int keepAliveSeconds) {
        this.coreThreads = core;
        this.maxThreads = max;
        this.queueSize = queueSize;
        this.keepAliveSeconds = keepAliveSeconds;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof ThreadPoolConfig)) {
            return false;
        }
        ThreadPoolConfig t = (ThreadPoolConfig) o;
        return keepAliveSeconds == t.keepAliveSeconds && queueSize == t.queueSize && maxThreads == t.maxThreads
                && coreThreads == t.coreThreads;
    }

    // don't really need to being a good citizen
    @Override
    public int hashCode() {
        return keepAliveSeconds + queueSize + maxThreads + coreThreads;
    }
}
