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
 * Portions Copyrighted [2011] [ForgeRock AS]
 * Portions Copyrighted [2015] [Intellectual Reserve, Inc (IRI)]
 */
package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.PacketType;

/**
 * Represents in java object for the Access-Request packet specified in section 4.1 of RFC 2865.
 */
public class AccessRequest extends Packet {
    /**
     * Instantiate an AccessRequest to be populated through setters.
     */
    public AccessRequest() {
        super(PacketType.ACCESS_REQUEST);
    }

    /**
     * Constructs a new Instance from the packet identifier and authenticator containing a 16 octet random number.
     * Both concepts are outlined in section 3 of RFC 2865.
     *
     * @param id the packet identifier
     * @param auth authenticator containing a 16 octet random number
     */
    public AccessRequest(short id, Authenticator auth) {
        super(PacketType.ACCESS_REQUEST, id, auth);
    }

}
