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
 * Class representing the structure of the Framed-IPX Address attribute as specified in section 5.24 of RFC 2865.
 */
public class FramedIPXNetworkAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of this attribute.
     */
    private byte [] octets = null;
    /**
     * The IPX Network number.
     */
    private byte [] net = new byte[4];

    /**
     * Constructs an instance of the specified type.
     * @param octets the FramedIPX network packet
     */
    public FramedIPXNetworkAttribute(byte [] octets) {

        super(FRAMED_IPX_NETWORK);
        net[0] = octets[2];
        net[1] = octets[3];
        net[2] = octets[4];
        net[3] = octets[5];
        this.octets = octets;

    }

    /**
     * Constructs an instance of the specified type.
     * Builds a FramedIPXNetwork Packet from received byte input
     * @param msb the most significant bit of the Framed IPX network address
     * @param msb2 the 2nd most significant byte of the IPX network address
     * @param msb3 the 3rd most significant byte of the IPX network address
     * @param msb4 the 4th most significant bit of hte Framed IPX network address
     */
    public FramedIPXNetworkAttribute(int msb, int msb2, int msb3, int msb4) {
        super(FRAMED_IPX_NETWORK);
        octets = new byte[6];
        octets[0] = (byte) super.getType();
        octets[1] = (byte) 6;
        octets[2] = (byte) msb;
        octets[3] = (byte) msb2;
        octets[4] = (byte) msb3;
        octets[5] = (byte) msb4;
    }

    /**
     * Returns the on-the-wire representation of the Framed IPX packet.
     * @return the on-the-wire representation of the FramedIPX packet.
     */
    public byte[] getValue() {
        return octets;
    }

    /**
     * Returns the IPX network address.
     *
     * @return the IPX network address
     */
    public byte[] getIPXNetworkAddress() {
        return net;
    }
}
