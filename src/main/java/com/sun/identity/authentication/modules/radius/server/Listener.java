package com.sun.identity.authentication.modules.radius.server;

import com.sun.identity.authentication.modules.radius.server.config.ClientConfig;
import com.sun.identity.authentication.modules.radius.server.config.Constants;
import com.sun.identity.authentication.modules.radius.server.config.RadiusServiceConfig;
import com.sun.identity.authentication.modules.radius.server.config.ThreadPoolConfig;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.DatagramChannel;
import java.text.MessageFormat;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Listens for incoming radius requests, validates they are for defined clients, drops packets that aren't, and
 * queues for handling those that are. If the listener is being shutdown then it accepts packets and drops them to
 * drain any buffered incoming requests which packets in process of being handled are polished off and can send their
 * responses through the backing channel. Then it closes the channel and exits.
 *
 * Created by markboyd on 11/13/14.
 */
public class Listener implements Runnable {
    private static final Logger cLog = Logger.getLogger(Listener.class.getName());

    /**
     * The configuration values for the Radius service pulled from OpenAM admin console constructs.
     */
    private RadiusServiceConfig config;

    private ThreadPoolExecutor pool = null;

    private boolean startedSuccessfully = false;
    private boolean terminated = false;
    private DatagramChannel channel = null;

    /**
     * The thread instance that is running this Runnable.
     */
    private Thread listenerThread = null;

    /**
     * Construct listener, opens the DatagramChannel to receive requests, sets up the thread pool, and launches the
     * listener's thread which will capture the requests, drop unauthorized clients, and spool to the thread pool.
     * @param config
     */
    public Listener(RadiusServiceConfig config) {
        cLog.log(Level.INFO, "RADIUS service enabled. Starting Listener.");
        this.config = config;

        // lets get our inbound channel opened and bound
        try {
            this.channel = DatagramChannel.open();
            // ensure that we can re-open port immediately after shutdown when changing handlerConfig
            this.channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        } catch (IOException e) {
            cLog.log(Level.SEVERE, "RADIUS listener unable to open datagram channel.", e);
            this.startedSuccessfully = false;
            return;
        }

        try {
            this.channel.socket().bind(new InetSocketAddress(config.getPort()));
        } catch (SocketException e) {
            cLog.log(Level.SEVERE, "RADIUS listener unable to bind to port " + config.getPort(), e);
            this.startedSuccessfully = false;
            return;
        }

        // now set up our thread pool
        ThreadPoolConfig poolCfg = config.getThreadPoolConfig();
        ArrayBlockingQueue<Runnable> queue = new ArrayBlockingQueue<Runnable>(poolCfg.queueSize);
        DroppedRequestHandler dropsHandler = new DroppedRequestHandler();

        ThreadFactory fact = new RadiusThreadFactory();

        pool = new ThreadPoolExecutor(poolCfg.coreThreads, poolCfg.maxThreads, poolCfg.keepAliveSeconds,
                TimeUnit.SECONDS, queue, fact, dropsHandler);

        // now spin up our listener thread to feed the pool
        listenerThread = new Thread(this);
        listenerThread.setName(MessageFormat.format(Constants.LISTENER_THREAD_NAME, config.getPort()));
        listenerThread.setDaemon(true);
        listenerThread.start();
        this.startedSuccessfully = true;
    }

    /**
     * Indicates if the constructor successfully started up the listener.
     * @return
     */
    public boolean isStartedSuccessfully() {
        return this.startedSuccessfully;
    }

    /**
     * Updates the configuration seen by this listener but should only be called when changes between the new handlerConfig
     * and the only are limited to changes in the set of defined clients. Any other change requires that the listener
     * be shutdown and possibly restarted.
     * @param config
     */
    public void updateConfig(RadiusServiceConfig config) {
        this.config = config;
    }

    /**
     * Blocking call that terminates the thread pool, tells the listener to drop any new requests, waits until the
     * thread pool is empty, and then interrupts the listener thread in case it is blocked waiting for new requests.
     * We must wait for the pool to empty before interrupting the listener thread since that closes the channel if
     * the thread is blocked on waiting for a new request and a closed channel then throws exceptions when any
     * request handlers in-progress attempt to send their responses to their clients.
     */
    public void terminate() {
        // tell listener to stop accepting requests if any come in while pool is shutting down
        this.terminated = true;

        // tell the pool to shutdown and stop accepting requests
        pool.shutdown();

        // now wait until the pool is finished
        boolean finished = false;
        boolean interrupted = false;

        while(! finished) {
            try {
                cLog.log(Level.WARNING, "Waiting for RADIUS thread pool's " + pool.getActiveCount()
                        + " request handler(s) to finish processing.");
                finished = pool.awaitTermination(Constants.THREAD_POOL_SHUTDOWN_WAIT_SECONDS, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        // now that all in-process requests are finished with the channel we can interrupt the listener if it is still
        // around (like when it was waiting for more requests prior to termination and received none and needs to be
        // kicked out of receiving mode
        Thread t = listenerThread;
        if (t != null) {
            t.interrupt();

            while (listenerThread != null) {
                cLog.log(Level.WARNING, "Waiting for RADIUS Listener to exit.");
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                }
            }
        }
    }

    /**
     * Where the work gets done. :-) Blocks until packets are recieved, validates the source IP against configured
     * clients and drops packets accordingly, then spools valid ones to the thread pool for handling and goes back to
     * listening.
     */
    @Override
    public void run() {
        boolean terminated = false;
        boolean interrupted = false;

        dumpBannerToLog();

        while (!terminated && !interrupted) {
            try {
                // assure big-endian (network) byte order for our buffer
                ByteBuffer bfr = ByteBuffer.allocate(Constants.MAX_PACKET_SIZE);
                bfr.order(ByteOrder.BIG_ENDIAN);
                InetSocketAddress iAddr = null;

                // see if we have a datagram packet waiting for us
                try {
                    iAddr = (InetSocketAddress) channel.receive(bfr);
                    if (iAddr == null) {
                        continue; // no datagram was available, it happens, just go back to listening
                    }
                } catch (ClosedByInterruptException c) {
                    interrupted = true;
                    continue;
                } catch (IOException e) {
                    cLog.log(Level.INFO, "Exception Receiving RADIUS packet. Ignoring.", e);
                    continue;
                }
                // see if it is for a registered client
                String ipAddr = iAddr.getAddress().toString();
                ClientConfig clientConfig = config.findClient(ipAddr);

                if (clientConfig == null) {
                    cLog.log(Level.WARNING, "No Defined RADIUS Client matches IP address " + ipAddr
                    + ". Dropping request.");
                    continue;
                }
                if (! clientConfig.classIsValid) {
                    cLog.log(Level.WARNING, "Declared Handler Class for Client '" + clientConfig.name +
                            "' is not valid. See earlier loading exception. Dropping request.");
                    continue;
                }
                // prepare buffer for draining and queue up a handler
                bfr.flip();
                RadiusRequestContext reqCtx = new RadiusRequestContext(clientConfig, channel, iAddr);

                pool.execute(new RadiusRequestHandler(reqCtx, bfr));
            }
            catch(Throwable t) {
                cLog.log(Level.SEVERE, "Error receiving request.", t);
            }
        }
        // reassert interrupted state if it occurred
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        try {
            // be sure that channel is closed
            channel.close();
        }
        catch(Exception e) {
            // ignore
        }
        cLog.log(Level.INFO, "RADIUS Listener Exited.");
        this.listenerThread = null;
    }

    private void dumpBannerToLog() {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("RADIUS Listener is Active.");
        pw.println("Port              : " + config.getPort());
        pw.println("Threads Core      : " + config.getThreadPoolConfig().coreThreads);
        pw.println("Threads Max       : " + config.getThreadPoolConfig().maxThreads);
        pw.println("Thread Keep-alive : " + config.getThreadPoolConfig().keepAliveSeconds + " sec");
        pw.println("Request Queue     : " + config.getThreadPoolConfig().queueSize);
        pw.flush();

        cLog.log(Level.INFO, sw.toString());
    }
}
