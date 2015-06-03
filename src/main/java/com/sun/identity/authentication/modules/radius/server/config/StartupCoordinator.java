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

import com.sun.identity.setup.AMSetupServlet;

/**
 * Responsible for delaying RADIUS server startup until configuration data can be read from openAM. Created by markboyd
 * on 11/12/14.
 */
public class StartupCoordinator {
    private static final Logger cLog = Logger.getLogger(StartupCoordinator.class.getName());

    /**
     * Blocking method until openam startup is completed or we are unable to make that determination. Returns true if it
     * is ready and false otherwise.
     */
    public boolean waitForOpenAMStartupCompletion() {
        boolean openAmIsReady = false;

        while (!openAmIsReady) {
            openAmIsReady = AMSetupServlet.isCurrentConfigurationValid();

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                cLog.log(Level.SEVERE, "Interrupted while waiting for for OpenAM to start up. Existing Radius "
                        + this.getClass().getSimpleName() + ".");
                return false;
            }
        }
        return true;
    }
}
