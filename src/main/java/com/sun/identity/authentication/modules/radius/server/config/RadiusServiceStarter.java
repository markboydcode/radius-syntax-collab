package com.sun.identity.authentication.modules.radius.server.config;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.modules.radius.server.Listener;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceManager;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.AccessController;
import java.text.MessageFormat;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is the startup point for the RADIUS server feature in OpenAM. TODO - By including its full package path in
 * SpringFrameworks component-scan directive in the WEB-INF/lds-extensions-servlet.xml file for Spring's Dispatcher
 * servlet named 'lds-extensions' in web.xml, this class is seen as a Controller and Spring sees that it implements
 * ServletContextAware and hands the ServletContext to us. At that point it starts a never ending thread that
 * coordinates the RADIUS server activities which include:
 *
 * <pre>
 * + Waiting for OpenAM to finish starting up.
 * + Read the configuration as entered in the admin console and create a map of client objects so that each client's ip
 * address, shared secret, name, and realm/authentication chain are known.
 * + Register a listener for configuration changes to the admin console information and when seen, updates the client
 * object set and listener.
 * + Opens the UDP listener on the port specified if 'isEnabled' is 'YES' or closes it if a
 * change notification shows that it has now been disabled.
 * </pre>
 *
 * Created by markboyd on 11/9/14.
 */

public class RadiusServiceStarter implements Runnable {
    private static final Logger cLog = Logger.getLogger(RadiusServiceStarter.class.getName());

    /**
     * Items appearing in this queue indicates that we need to refresh our configuration. A queue was selected for the
     * rare event of an admin changing one field, hitting save, then changing another and hitting save and the loading
     * steps could potentially miss the latter change. Whereas we can reload multiple times and adjust services
     * accordingly without difficulty. So we queue each call to the change listener and reload for each event. However,
     * since we are comparing processing time with user input we don't need lots of slots since processing should beat
     * the user. But it loading took long enough we might get another change queued up. And if it was taking that long
     * then I don't care if we lose any further change events since there are at least two in the queue that will force
     * reloading. Hence why the queue isn't longer.
     */
    private ArrayBlockingQueue<String> configChangedQueue = new ArrayBlockingQueue<String>(2);

    /**
     * The current handlerConfig loaded from openAM's admin console constructs. When handlerConfig changes are detected we reload and
     * compare the new to the old and adjust accordingly. The defaults have RADIUS authentication disabled, and no
     * thread pool handlerConfig which is ok since these won't be used due to injecting the offer into the configChangedQueue
     * causes immediate loading from openAM persisted values.
     */
    private RadiusServiceConfig currentCfg = new RadiusServiceConfig(false, Constants.RADIUS_AUTHN_PORT, null);

    /**
     * The current listener instance if any.
     */
    private Listener listener = null;

    /**
     * The loader of our service's OpenAM console configuration values.
     */
    private ConfigLoader loader = null;

    /**
     * The thread that we launch to run this Runnable. Reference is needed in the event we need to shut down.
     */
    private Thread coordinatingThread = null;

    /**
     * The singleton instance of the starter.
     */
    private static final RadiusServiceStarter starter = new RadiusServiceStarter();

    /**
     * Accessor of the singleton instance.
     *
     * @return
     */
    public static final RadiusServiceStarter getInstance() {
        return starter;
    }

    /**
     * Loads and logs the build version of our module.
     */
    static {
        RadiusServiceStarter.logModuleBuildVersion();
    }

    /**
     * Loads and logs the build version of our module. Public so ConsoleClient can also call.
     */
    public static final void logModuleBuildVersion() {
        try {
            InputStream is = RadiusServiceStarter.class.getResourceAsStream("/META-INF/openam-radius-version.txt");
            if (is != null) {
                int bytesRead = 0;

                byte[] bytes =  new byte[256];
                try {
                    bytesRead = is.read(bytes);
                    cLog.log(Level.INFO, "Loaded " + new String(bytes, 0, bytesRead));
                } catch (IOException e) {
                    cLog.log(Level.WARNING, "----> Unable to load openam-auth-smsotp module's version information.", e);
                }
            }
        }
        catch(Throwable t) {
            cLog.log(Level.SEVERE, "----> Unable to load openam-auth-smsotp module's version information.", t);
        }
    }


    /**
     * Creates the instance of the starter.
     */
    private RadiusServiceStarter() {
    }

    /**
     * Tells the service to shut down. Only returns after all lanched threads and thread pools have been shutdown.
     */
    void shutdown() {
        Thread coordinator = coordinatingThread;

        if (coordinator != null) {
            String name = coordinator.getName();
            cLog.log(Level.INFO, this.getClass().getSimpleName() + " interrupting " + name);
            coordinator.interrupt();

            while (coordinatingThread != null) {
                cLog.log(Level.WARNING, "Waiting for " + name + " to exit.");
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                }
            }
        }
    }

    /**
     * Launches the Radius Server. May be called more than once if more than one
     * trigger is registered such as a SpringFramework servlet and the ServletContextListener. Only the first
     * call will start the process. All others are ignored.
     *
     */
    public synchronized void startUp() {
        if (coordinatingThread == null) {

            // force a change event to tell the controller to load handlerConfig
            configChangedQueue.offer("Loading RADIUS Config...");

            Thread t = new Thread(this);
            t.setName(MessageFormat.format(Constants.COORDINATION_THREAD_NAME, this.getClass().getSimpleName()));
            t.setDaemon(true);
            t.start();
            coordinatingThread = t;
        }
        else {
            cLog.log(Level.WARNING, this.getClass().getSimpleName() + ".setServletConfig() called again. Service " +
                    "already started. Ignoring.");
        }
    }

    @Override
    public void run() {
        // delay reading openam handlerConfig until openam is running
        StartupCoordinator startupCoord = new StartupCoordinator();
        boolean openamReady = startupCoord.waitForOpenAMStartupCompletion();

        if (!openamReady) {
            cLog.log(Level.SEVERE, "RADIUS Service Unavailable. Unable to read OpenAM handlerConfig.");
            // things are looking bad for our hero. Nothing to do but exit the thread and give up on RADIUS features.
            this.coordinatingThread = null;
            return;
        }
        // make sure our service descriptor is loaded into openam before attempting to load that configuration
        ensureDescriptorLoaded(Constants.RADIUS_SERVICE_NAME, Constants.RADIUS_SERVICE_CFG_FILE);

        // kick off config loading and registration of change listener
        loader = new ConfigLoader();
        String changeMsg = null;

        try {
            while (true) {
                // wait until we see a handlerConfig change
                changeMsg = configChangedQueue.take();
                // wait for changes to take effect
                Thread.sleep(1000);
                // load our handlerConfig
                cLog.log(Level.INFO, changeMsg);
                RadiusServiceConfig cfg = loader.loadConfig(configChangedQueue);
                if (cfg != null) {
                    cLog.log(Level.INFO, "--- Loaded Config ---\n" + cfg);
                }

                if (cfg == null) {
                    cLog.log(Level.INFO, "Unable to load RADIUS Config. Ignoring change.");
                    // nothing to be done. lets wait for another handlerConfig event and maybe it will be loadable then
                    continue;
                }

                if (listener == null) { // at startup or after service has been turned off
                    if (cfg.isEnabled()) {
                        listener = new Listener(cfg);
                    }
                    else {
                        cLog.log(Level.INFO, "RADIUS service disabled.");
                    }
                }
                else { // so we already have a listener running
                    if (onlyClientSetChanged(cfg, currentCfg)) {
                        listener.updateConfig(cfg);
                    }
                    else {
                        // all other changes (port, thread pool values, enabledState) require restart of listener
                        listener.terminate();
                        listener = null;
                        if (cfg.isEnabled()) {
                            listener = new Listener(cfg);
                        }
                        else {
                            cLog.log(Level.INFO, "RADIUS service NOT enabled.");
                        }
                    }
                }
                currentCfg = cfg;
            }
        } catch (InterruptedException e) {
            cLog.log(Level.INFO, Thread.currentThread().getName() + " interrupted. Exiting.");
        }
        // shutting down so terminate the listener and thread pools
        Listener l = listener;

        if (l != null) {
            l.terminate();
        }
        loader.notifyHandlerShutdownListeners();
        cLog.log(Level.INFO, Thread.currentThread().getName() + " exited.");
        this.coordinatingThread = null;
    }

    /**
     * Tests whether a config service's descriptor file has been loaded into openam thus making that config
     * available and loading it if it hasn't.
     * @param serviceName the name of the config service registered via the service descriptor file
     * @param cfgFile the classpath based path to the service descriptor file
     */
    private void ensureDescriptorLoaded(String serviceName, String cfgFile) {
        // get the admin access token for instantiating the ServiceManager and ServiceConfigManager instances
        SSOToken admTk = AccessController.doPrivileged(
                AdminTokenAction.getInstance());

        // get ServiceManager to see the list of all registered services and see if ours is in there
        ServiceManager sm = null;
        try {
            sm = new ServiceManager(admTk);
        } catch (Exception e) {
            e.printStackTrace();
        }
        boolean serviceExists = false;
        Set names = null;
        try {
            names = sm.getServiceNames();
        } catch (Exception e) {
            cLog.log(Level.SEVERE, "Unable to obtain service names from ServiceManager to determine if "
                + serviceName + " is already registered or needs its service descriptor file "
                    + cfgFile + " loaded. Assuming that it already loaded.", e);
            return;
        }
        for(Object o : names) {
            String name = (String) o;
            if (serviceName.equals(name)) {
                serviceExists = true;
            }
        }

        // so ours isn't in there. Lets go register it.
        if (! serviceExists) {
            cLog.log(Level.INFO, serviceName + " not found. Loading...");
            ServiceConfigManager mgr = null;
            try {
                mgr = new ServiceConfigManager(serviceName, admTk);
            } catch (Exception e) {
                cLog.log(Level.SEVERE, "Unable to obtain ServiceConfigManager to load " + cfgFile
                        + ". Not loading.", e);
                return;
            }
            URL url = this.getClass().getClassLoader().getResource(cfgFile);

            if (url == null) {
                cLog.log(Level.SEVERE, "Unable to locate classpath resource '" + cfgFile
                        + "'. Must be loaded before the " + serviceName + " will be available in the admin console.");
                return;
            }
            cLog.log(Level.INFO, "Service Descriptor file for " + serviceName + " found at: " + url.toString());

            InputStream is = null;
            try {
                is = url.openStream();
            } catch (Exception e) {
                cLog.log(Level.SEVERE, "Unable to open resource " + url.toString()
                        + ". Must be loaded before the " + serviceName + " will be available in the admin console.", e);
                return;
            }
            try {
                sm.registerServices(is);
            }
            catch(Exception e) {
                cLog.log(Level.SEVERE, "Unable to load " + cfgFile + " file. Must be loaded before the "
                        + serviceName + " will be available in the admin console.", e);
                return;
            }
            finally {
                try {
                    is.close();
                }
                catch(Exception e) {
                    // ignore
                }
            }
            // wait one second for service cache update
            try {
                Thread.sleep(1000);
            }
            catch(InterruptedException e) {
                // ignore but move on since we'll exit out pretty quickly
            }
        }
    }

    /**
     * Returns true if the only changes made are the addition, changing, or removal of the defined set of clients.
     *
     * @param cfg
     * @param currentCfg
     * @return
     */
    private boolean onlyClientSetChanged(RadiusServiceConfig cfg, RadiusServiceConfig currentCfg) {

        return cfg.getPort() == currentCfg.getPort() && cfg.isEnabled() == currentCfg.isEnabled()
        && cfg.getThreadPoolConfig() != null && cfg.getThreadPoolConfig().equals(currentCfg.getThreadPoolConfig());
    }
}
