package com.sun.identity.authentication.modules.radius.server.poc;


import java.nio.channels.DatagramChannel;
import java.text.DecimalFormat;

/**
 *
 * Created by markboyd on 6/28/14.
 */
public class Context {



    /**
     * Formatter for elapsed times in miliseconds
     */
    public static final DecimalFormat ELAPSED_SECONDS_FORMATTER = new DecimalFormat("##");


    /**
     * The DatagramSocket on which this server is listening for packets.
     */
    public DatagramChannel channel = null;
}
