package com.sun.identity.authentication.modules.radius.server.config;

import com.sun.identity.log.Level;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.logging.Logger;

/**
 * Wrapper for the RadiusServiceStarter enabling ServletContextListener startup.
 *
 * Created by markboyd on 12/12/14.
 */
public class ServletContextListenerLauncher implements ServletContextListener {
    private static final Logger cLog = Logger.getLogger(ServletContextListenerLauncher.class.getName());

    /**
     * Delegates to the starter to fire up the Radius Service.
     * @param sce
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        try {
            cLog.log(Level.INFO, "---> " + this.getClass().getSimpleName() + " starting "
             + RadiusServiceStarter.class.getSimpleName());
            RadiusServiceStarter.getInstance().startUp();
        }
        catch(Throwable t) {
            System.out.println("Oops. Problem here.");
            t.printStackTrace();
        }

    }

    /**
     * Tells the Radius Service to shutdown.
     * @param sce
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        cLog.log(Level.INFO, "---> " + this.getClass().getSimpleName() + " stopping "
                + RadiusServiceStarter.class.getSimpleName());
        RadiusServiceStarter.getInstance().shutdown();
    }
}
