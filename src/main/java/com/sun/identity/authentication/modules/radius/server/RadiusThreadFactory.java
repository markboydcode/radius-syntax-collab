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
package com.sun.identity.authentication.modules.radius.server;

import java.text.MessageFormat;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.identity.authentication.modules.radius.server.config.Constants;

/**
 * Creates threads with name RADIUS-Request-Handler-# with # being the index of creation. Sets the thread group to that
 * of the calling thread and sets priority to the lesser of Thread.NORM_PRIORITY or the thread group's max priority.
 * This follows the general design of Executors.defaultThreadFactory save for the custom name. Created by markboyd on
 * 11/18/14.
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
