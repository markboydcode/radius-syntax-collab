package com.sun.identity.authentication.modules.radius.server.config;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * Holds the suite of configuration from the admin console for rapid determination of whether packets should be dropped
 * or accepted and processed.
 *
 * Created by markboyd on 11/11/14.
 */
public class RadiusServiceConfig {
    /**
     * Configuration properties of the thread pool for handling requests.
     */
    private ThreadPoolConfig threadPoolConfig;

    /**
     * The set of configured clients.
     */
    private Map<String, ClientConfig> clients = new HashMap<String, ClientConfig>();


    /**
     * Whether the port should be opened and we should be listening for incoming UDP packet requests. By default we set
     * it to false when instantiated and then set the value to reflect what is
     */
    private boolean isEnabled = false;

    /**
     * The port address on which we should be listening when enabled.
     */
    private int port = -1;

    /**
     * Instance created from loading handlerConfig from openAM's admin console constructs.
     *
     * @param isEnabled
     * @param port
     * @param clientConfigs
     */
    public RadiusServiceConfig(boolean isEnabled, int port, ThreadPoolConfig poolCfg, ClientConfig... clientConfigs) {
        this.isEnabled = isEnabled;
        this.port = port;
        this.threadPoolConfig = poolCfg;

        for(ClientConfig c : clientConfigs) {
            this.clients.put(c.ipaddr, c);
        }
    }

    /**
     * Get the thread pool configuration values.
     *
     * @return
     */
    public ThreadPoolConfig getThreadPoolConfig() {
        return this.threadPoolConfig;
    }

    /**
     * Returns the defined client for the given IP address or null if not client for that IP address is defined.
     *
     * @param ipAddress
     * @return
     */
    public ClientConfig findClient(String ipAddress) {
        return clients.get(ipAddress);
    }

    /**
     * Returns true if the RADIUS service should have an open UDP Datagram Channel listening for incoming packets.
     * Returns false if the RADIUS service should NOT be listening for and accepting packets.
     * @return
     */
    public boolean isEnabled() {
        return this.isEnabled;
    }

    /**
     * The port to which the RADIUS service should have a bound Datagram Channel listening for incoming packets if
     * isEnabled() returns true.
     *
     * @return
     */
    public int getPort() {
        return this.port;
    }

    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
//        pw.println("[" + this.getClass().getSimpleName());
//        pw.println(" Enabled : " + (isEnabled() ? "YES" : "NO"));
//        pw.println(" Port    : " + getPort());
//
//        ThreadPoolCfg pc = getThreadPoolConfig();
//        pw.println(" Thread-Pool");
//        pw.println("  CoreThreads      : " + pc.coreThreads);
//        pw.println("  MaxThreads       : " + pc.maxThreads);
//        pw.println("  KeepAliveSeconds : " + pc.keepAliveSeconds);
//        pw.println("  QueueSize        : " + pc.queueSize);
//        pw.println(" Clients");
//        for(Map.Entry<String, Client> ent : clients.entrySet()) {
//            Client c = ent.getValue();
//            pw.println("  " + c.ipaddr + " = " + c.name + " [" + c.secret + ", " + c.realm + c.authChain + "]");
//        }
//        pw.println("]");
        ThreadPoolConfig pc = getThreadPoolConfig();
        pw.print("[" + this.getClass().getSimpleName() + " " + (isEnabled() ? "YES" : "NO") +
                " " + getPort() + " P( " + pc.coreThreads + ", " + pc.maxThreads +
                ", " + pc.keepAliveSeconds + ", " + pc.queueSize + ")");
        for(Map.Entry<String, ClientConfig> ent : clients.entrySet()) {
            ClientConfig c = ent.getValue();
            pw.print(", C( " + c.ipaddr + "=" + c.name + ", " + c.secret + ", " + c.logPackets + ", "
                    + (c.classIsValid ? c.clazz.getName() : "not-found: " + c.classname) + ", " +
                    c.handlerConfig + ")");
        }
        pw.println("]");
        pw.flush();
        return sw.toString();

    }
}
