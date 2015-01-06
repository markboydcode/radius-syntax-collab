package com.sun.identity.authentication.modules.radius.server.poc;

import com.toopher.ToopherAPI;

import java.nio.channels.DatagramChannel;
import java.text.DecimalFormat;

/**
 *
 * Created by markboyd on 6/28/14.
 */
public class Context {

    /**
     * The handle to the toopher REST api.
     */
    public ToopherAPI toopherApi;

    /**
     * Formatter for elapsed times in miliseconds
     */
    public static final DecimalFormat ELAPSED_SECONDS_FORMATTER = new DecimalFormat("##");


    /**
     * The DatagramSocket on which this server is listening for packets.
     */
    public DatagramChannel channel = null;
}
