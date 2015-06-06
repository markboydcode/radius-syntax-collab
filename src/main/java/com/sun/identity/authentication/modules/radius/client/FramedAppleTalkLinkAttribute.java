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
 * Class representing the structure of the Framed-AppleTalk-Link attribute as specified in section 5.37 of RFC 2865.
 */
public class FramedAppleTalkLinkAttribute extends Attribute {
    /**
     * The special link value that indicates an unnumbered link.
     */
    public static final int UN_NUMBERED = 0;

    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;

    /**
     * The network number value between 0 and 65535.
     */
    private int networkNumber = 0;

    /**
     * Construct a new instance from the network number it should represent between 0 and 65535 notwithstanding use
     * of an integer. The int type is used since short types in java are signed and hence can't represent an unsigned
     * value of 32786 or greater. A value of 0 indicates an unnumbered link.
     *
     * @param networkNumber the network number that should be between 0 and 65535 inclusive.
     */
    public FramedAppleTalkLinkAttribute(int networkNumber) {
        super(FRAMED_APPLETALK_LINK);
        octets = new byte[6];
        octets[0] = (byte) super.getType();
        octets[1] = 6;
        octets[2] = (byte) ((networkNumber >>> 24) & 0xFF);
        octets[3] = (byte) ((networkNumber >>> 16) & 0xFF);
        octets[4] = (byte) ((networkNumber >>> 8) & 0xFF);
        octets[5] = (byte) (networkNumber & 0xFF);
        this.networkNumber = networkNumber;
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FramedAppleTalkLinkAttribute(byte[] octets) {
        super(FRAMED_APPLETALK_LINK);
        this.octets = octets;
        networkNumber = octets[5] & 0xFF;
        networkNumber |= ((octets[4] << 8) & 0xFF00);
        networkNumber |= ((octets[3] << 16) & 0xFF0000);
        networkNumber |= ((octets[2] << 24) & 0xFF000000);
    }

    /**
     * Returns the apple talk network number between 0 and 65535.
     *
     * @return the apple talk network number.
     */
    public int getNetworkNumber() {
        return networkNumber;
    }

    /**
     * Indicates if this is for an unnumbered serial link.
     *
     * @return true if this is an unnumbered link, false if it is numbered.
     */
    public boolean isUnumberedLink() {
        return networkNumber == UN_NUMBERED;
    }

    /**
     * Returns the on-the-wire bytes used to construct this instance.
     *
     * @return the on-the-wire byte representation of this attribute.
     */
    public byte[] getValue() {
        byte[] p = new byte[6];
        p[0] = (byte) super.getType();
        p[1] = 6;
        p[2] = (byte) ((networkNumber >>> 24) & 0xFF);
        p[3] = (byte) ((networkNumber >>> 16) & 0xFF);
        p[4] = (byte) ((networkNumber >>> 8) & 0xFF);
        p[5] = (byte) (networkNumber & 0xFF);
        return p;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return content representation for traffic logging
     */
    public String toStringImpl() {

        return new StringBuilder().append(networkNumber).toString();
    }
}
