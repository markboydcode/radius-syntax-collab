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

import java.io.IOException;

/**
 * Class representing the structure of the Callback-Id attribute as specified in section 5.20 of RFC 2865 and able to
 * be instantiated from the on-the-wire bytes.
 */
public class CallbackIdAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;

    /**
     * The callback id value.
     */
    private String str = null;

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute.
     *
     * @param octets the on-the-wire octets from which to instantiate this instance
     */
    public CallbackIdAttribute(byte[] octets) {
        super(CALLBACK_ID);
        str = new String(octets, 2, octets.length - 2);
        this.octets = octets;
    }

    /**
     * Returns the callback id.
     *
     * @return the callback id value for this attribute
     */
    public String getString() {
        return str;
    }

    /**
     * Returns the on-the-wire bytes used to construct this instance.
     *
     * @return the on-the-wire octet representation of this attribute
     * @throws java.io.IOException if unable to generate on-the-wire octet representation of the attribute
     */
    public byte[] getValue() throws IOException {
        return octets;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return the content representation to be used during traffic logging
     */
    public String toStringImpl() {
        return str;
    }
}
