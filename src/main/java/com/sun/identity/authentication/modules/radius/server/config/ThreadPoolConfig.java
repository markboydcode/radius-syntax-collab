package com.sun.identity.authentication.modules.radius.server.config;

/**
 * Configuration values for the thread pool loaded from OpenAM's admin console constructs.
 *
 * Created by markboyd on 11/13/14.
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
        if (o == null || ! (o instanceof ThreadPoolConfig)) {
            return false;
        }
        ThreadPoolConfig t = (ThreadPoolConfig) o;
        return keepAliveSeconds == t.keepAliveSeconds &&
                queueSize == t.queueSize &&
                maxThreads == t.maxThreads &&
                coreThreads == t.coreThreads;
    }


    // don't really need to being a good citizen
    @Override
    public int hashCode() {
        return keepAliveSeconds + queueSize + maxThreads + coreThreads;
    }
}
