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

/**
 * Class representing the structure of the Calling-Station-Id attribute as specified in section 5.31 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes.
 */
public class CallingStationIdAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;
    /**
     * The id of the station making the call.
     */
    private String str = null;

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public CallingStationIdAttribute(byte[] octets) {
        super(CALLING_STATION_ID);
        str = new String(octets, 2, octets.length - 2);
        this.octets = octets;
    }

    /**
     * Returns the station id.
     *
     * @return the station id
     */
    public String getString() {
        return str;
    }

    /**
     * Returns the on-the-wire bytes used to construct this instance.
     *
     * @return the on-the-wire byte representation of this attribute.
     */
    public byte[] getValue() {
        return octets;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return content representation for traffic logging
     */
    public String toStringImpl() {
        return str;
    }
}
