package com.sun.identity.authentication.modules.radius.server.config;

import com.sun.identity.setup.AMSetupServlet;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Responsible for delaying RADIUS server startup until configuration data can be read from openAM.
 *
 * Created by markboyd on 11/12/14.
 */
public class StartupCoordinator {
    private static final Logger cLog = Logger.getLogger(StartupCoordinator.class.getName());

    /**
     * Blocking method until openam startup is completed or we are unable to make that determination. Returns true if it
     * is ready and false otherwise.
     */
    public boolean waitForOpenAMStartupCompletion() {
        boolean openAmIsReady = false;

        while (! openAmIsReady) {
            openAmIsReady = AMSetupServlet.isCurrentConfigurationValid();

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                cLog.log(Level.SEVERE, "Unable to see if OpenAM config is valid. Hence can't start up RADIUS service coordinator.", e);
                return false;
            }
        }
        return true;
    }
}
