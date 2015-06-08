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
 * Class representing the structure of the Framed-MTU attribute as specified in section 5.12 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes or from model objects.
 */
public class FramedMTUAttribute extends Attribute {
    private byte[] octets = null;
    private int mtu = 0;

    /**
     * Constructs a new instance from the Maximum Transmission Unit for this attribute.
     *
     * @param mtu the Maximum Transmission Unit.
     */
    public FramedMTUAttribute(int mtu) {
        octets = new byte[6];
        octets[0] = FRAMED_MTU;
        octets[1] = 6;
        octets[2] = (byte) ((mtu >>> 24) & 0xFF);
        octets[3] = (byte) ((mtu >>> 16) & 0xFF);
        octets[4] = (byte) ((mtu >>> 8) & 0xFF);
        octets[5] = (byte) (mtu & 0xFF);
        this.mtu = mtu;
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FramedMTUAttribute(byte[] octets) {
        super(FRAMED_MTU);
        this.octets = octets;
        mtu = octets[5] & 0xFF;
        mtu |= ((octets[4] << 8) & 0xFF00);
        mtu |= ((octets[3] << 16) & 0xFF0000);
        mtu |= ((octets[2] << 24) & 0xFF000000);
    }

    /**
     * Return the MTU.
     * @return the MTU.
     */
    public int getMtu() {
        return mtu;
    }

    /**
     * Get the on-the-wire octets for this attribute.
     *
     * @return the on-the-wire octets for this attribute.
     */
    public byte[] getValue() {
        return octets;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return the content representation to be used during traffic logging
     */
    public String toStringImpl() {
        return new StringBuilder().append(mtu).toString();
    }
}
