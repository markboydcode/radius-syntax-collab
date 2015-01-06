package com.sun.identity.authentication.modules.radius.server.poc;

import com.sun.identity.authentication.modules.radius.client.Authenticator;
import com.sun.identity.authentication.modules.radius.client.Packet;

import java.net.InetSocketAddress;

/**
 * Object for hand RADIUS request, address, and other information between handlers and methods.
 *
 * Created by markboyd on 6/28/14.
 */
public class RequestInfo {
    Packet pkt = null;
    InetSocketAddress addr = null;
    Authenticator authctr = null;
    String username = null;
    String credential = null;

    StateHolder stateHolder = null;

    String devicePairingId = null;
    public long start; // millis timestamp of when processing started for a request
    public boolean pairingStatusRetrieved = false;
    public boolean pairingWasEnabled = false;
    public boolean authenticationWasApproved = false;
    public boolean authenticationStatusRetrieved = false;

    /**
     * The shared secret for the client originating the packet in this request.
     */
    public String clientSecret;

    /**
     * The user's toopher pairing id if had. This field is used to pass such a value between methods.
     */
    //public String toopherPairingId;

    /**
     * The toopher authentication request id if and authentication is in process.
     */
    //public String toopherAuthNReqId;


}
