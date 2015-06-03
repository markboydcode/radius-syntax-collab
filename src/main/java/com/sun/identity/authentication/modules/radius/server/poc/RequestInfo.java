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
package com.sun.identity.authentication.modules.radius.server.poc;

import java.net.InetSocketAddress;

import com.sun.identity.authentication.modules.radius.client.Authenticator;
import com.sun.identity.authentication.modules.radius.client.Packet;

/**
 * Object for hand RADIUS request, address, and other information between handlers and methods. Created by markboyd on
 * 6/28/14.
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
    // public String toopherPairingId;

    /**
     * The toopher authentication request id if and authentication is in process.
     */
    // public String toopherAuthNReqId;

}
