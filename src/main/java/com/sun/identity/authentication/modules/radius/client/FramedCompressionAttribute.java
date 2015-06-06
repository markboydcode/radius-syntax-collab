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
 * Class representing the structure of the Framed-Compression attribute as specified in section 5.13 of RFC 2865.
 */
public class FramedCompressionAttribute extends Attribute {
    /**
     * This compression value indicates no compression.
     */
    public static final int NONE = 0;
    /**
     * This compression value indicates VJ TCP/IP header compression.
     */
    public static final int VJ_TCP_IP_HEADER = 1;
    /**
     * This compression value indicates IPX header compression.
     */
    public static final int IPX_HEADER = 2;
    /**
     * This compression value indicates Stac-LZS compression.
     */
    public static final int STAC_LZS = 3;

    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;

    /**
     * The compression type.
     */
    private int compression = 0;

    /**
     * Construct a new instance from the compression type.
     *
     * @param compression the compression type that should be applied
     */
    public FramedCompressionAttribute(int compression) {
        super(FRAMED_COMPRESSION);
        octets = new byte[6];
        octets[0] = (byte) super.getType();
        octets[1] = 6;
        octets[2] = (byte) ((compression >>> 24) & 0xFF);
        octets[3] = (byte) ((compression >>> 16) & 0xFF);
        octets[4] = (byte) ((compression >>> 8) & 0xFF);
        octets[5] = (byte) (compression & 0xFF);
        this.compression = compression;
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FramedCompressionAttribute(byte[] octets) {
        super(FRAMED_COMPRESSION);
        this.octets = octets;
        compression = octets[5] & 0xFF;
        compression |= ((octets[4] << 8) & 0xFF00);
        compression |= ((octets[3] << 16) & 0xFF0000);
        compression |= ((octets[2] << 24) & 0xFF000000);
    }

    /**
     * Returns the desired compression indicator.
     *
     * @return the compression indicator.
     */
    public int getCompression() {
        return compression;
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
        p[2] = (byte) ((compression >>> 24) & 0xFF);
        p[3] = (byte) ((compression >>> 16) & 0xFF);
        p[4] = (byte) ((compression >>> 8) & 0xFF);
        p[5] = (byte) (compression & 0xFF);
        return p;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return content representation for traffic logging
     */
    public String toStringImpl() {

        return new StringBuilder().append(compression).toString();
    }
}
