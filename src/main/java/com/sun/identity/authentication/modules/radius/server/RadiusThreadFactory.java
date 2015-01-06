package com.sun.identity.authentication.modules.radius.server;

import com.sun.identity.authentication.modules.radius.server.config.Constants;

import java.text.MessageFormat;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Creates threads with name RADIUS-Request-Handler-# with # being the index of creation. Sets the thread group to
 * that of the calling thread and sets priority to the lesser of Thread.NORM_PRIORITY or the thread group's
 * max priority. This follows the general design of Executors.defaultThreadFactory save for the custom name.
 *
 * Created by markboyd on 11/18/14.
 */
public class RadiusThreadFactory implements ThreadFactory {

    private AtomicInteger idx = new AtomicInteger(0);

    @Override
    public Thread newThread(Runnable task) {
        ThreadGroup grp = Thread.currentThread().getThreadGroup();
        String name = MessageFormat.format(Constants.REQUEST_HANDLER_THREAD_NAME, idx.incrementAndGet());
        Thread t = new Thread(grp, task, name);
        t.setPriority(Math.min(Thread.NORM_PRIORITY, grp.getMaxPriority()));
        return t;
    }
}
