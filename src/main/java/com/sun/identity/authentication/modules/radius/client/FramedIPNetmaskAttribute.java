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
 * Class representing the structure of the Framed-IP-Netmask attribute as specified in section 5.9 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes.
 */
public class FramedIPNetmaskAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;

    /**
     * The net mask.
     */
    private byte[] mask = new byte[4];

    /**
     * Construct an instance from the set of bytes for each address. We can't use a byte[] or it collides with the
     * footprint of the other constructor that uses the raw octets. The ordering is significant. The first parameter
     * is the most significant byte. The last is the least significant byte. So for a mask of 255.255.255.0 we would
     * perform:
     * <pre>
     *    new FramedIPNetmaskAttribute(255,255,255,0);
     * </pre>
     *
     * @param maskMsb the nost significant byte of address such as 255
     * @param maskMsb2 the next most significant byte such as 255
     * @param maskLsb2 the 3rd most significant byte such as 255
     * @param maskLsb the least significant byte such as 0
     */
    public FramedIPNetmaskAttribute(int maskMsb, int maskMsb2, int maskLsb2, int maskLsb) {
        super(FRAMED_IP_NETMASK);
        octets = new byte[6];
        octets[0] = (byte) super.getType();
        octets[1] = 6;
        octets[2] = (byte) maskMsb; // network byte order is big endian meaning most significant byte in lowest byte.
        octets[3] = (byte) maskMsb2;
        octets[4] = (byte) maskLsb2;
        octets[5] = (byte) maskLsb;
        this.mask = new FramedIPNetmaskAttribute(octets).getMask();
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FramedIPNetmaskAttribute(byte[] octets) {
        super(FRAMED_IP_NETMASK);
        mask[0] = octets[2];
        mask[1] = octets[3];
        mask[2] = octets[4];
        mask[3] = octets[5];
        this.octets = octets;
    }

    /**
     * Get the mask.
     *
     * @return the mask
     */
    public byte[] getMask() {
        return mask;
    }

    /**
     * Get the on-the-wire octets for this attribute.
     *
     * @return the on-the-wire octets for this attribute.
     */
    public byte[] getValue() {
        return octets;
    }
}
