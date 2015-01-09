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
                cLog.log(Level.SEVERE, "Interrupted while waiting for for OpenAM to start up. Existing Radius "
                + this.getClass().getSimpleName() + ".");
                return false;
            }
        }
        return true;
    }
}
