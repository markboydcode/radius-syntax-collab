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

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Wrapper for the RadiusServiceStarter enabling ServletContextListener startup. Created by markboyd on 12/12/14.
 */
public class ServletContextListenerLauncher implements ServletContextListener {
    private static final Logger cLog = Logger.getLogger(ServletContextListenerLauncher.class.getName());

    /**
     * Delegates to the starter to fire up the Radius Service.
     * 
     * @param sce
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        try {
            cLog.log(
                    Level.INFO,
                    "---> " + this.getClass().getSimpleName() + " starting "
                            + RadiusServiceStarter.class.getSimpleName());
            RadiusServiceStarter.getInstance().startUp();
        } catch (Throwable t) {
            System.out.println("Oops. Problem here.");
            t.printStackTrace();
        }

    }

    /**
     * Tells the Radius Service to shutdown.
     * 
     * @param sce
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        cLog.log(Level.INFO,
                "---> " + this.getClass().getSimpleName() + " stopping " + RadiusServiceStarter.class.getSimpleName());
        RadiusServiceStarter.getInstance().shutdown();
        cLog.log(Level.INFO, "RADIUS server context listener destroyed");
    }
}
