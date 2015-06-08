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
 * Class representing the structure of the Framed-IP-Address attribute as specified in section 5.8 of RFC 2865.
 */
public class FramedIPAddressAttribute extends Attribute {
    /**
     * Indicator of types of FramedIPAddressAttribute to be instantiated.
     */
    public static enum Type {
        /**
         * Indicates if the NAS should allow the user to select an address.
         */
        USER_NEGOTIATED,
        /**
         * Indicates if the NAS should select an address for the user.
         */
        NAS_ASSIGNED,
        /**
         * Indicates that the NAS should use that value as the user's IP address.
         */
        SPECIFIED;
    }

    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;
    /**
     * The ip address bytes.
     */
    private byte[] addr = new byte[4];

    /**
     * Constructs an instance of the specified type. For NAS_ASSIGNED and USER_NEGOTIATED the octets array is ignored.
     *
     * @param type the type of instance to create.
     * @param octets the network address for the SPECIFIED type.
     */
    public FramedIPAddressAttribute(Type type, byte[] octets) {
        this.octets = new byte[6];
        this.octets[0] = FRAMED_IP_ADDRESS;
        this.octets[1] = 6;

        if (type == Type.NAS_ASSIGNED) {
            this.octets[2] = (byte) 255;
            this.octets[3] = (byte) 255;
            this.octets[4] = (byte) 255;
            this.octets[5] = (byte) 254;
        } else if (type == Type.USER_NEGOTIATED) {
            this.octets[2] = (byte) 255;
            this.octets[3] = (byte) 255;
            this.octets[4] = (byte) 255;
            this.octets[5] = (byte) 255;
        } else { // is SPECIFIED
            this.octets[2] = octets[0];
            this.octets[3] = octets[1];
            this.octets[4] = octets[2];
            this.octets[5] = octets[3];
        }
        this.addr[0] = this.octets[2];
        this.addr[1] = this.octets[3];
        this.addr[2] = this.octets[4];
        this.addr[3] = this.octets[5];
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FramedIPAddressAttribute(byte[] octets) {
        super(FRAMED_IP_ADDRESS);
        addr[0] = octets[2];
        addr[1] = octets[3];
        addr[2] = octets[4];
        addr[3] = octets[5];
        this.octets = octets;
    }

    /**
     * Indicates if the NAS should allow the user to select an address.
     *
     * @return true if the NAS should allow the user to select
     */
    public boolean isUserNegotiated() {
        return (addr[0] == (byte) 255)
                && (addr[1] == (byte) 255)
                && (addr[2] == (byte) 255)
                && (addr[3] == (byte) 255);
    }

    /**
     * Indicates if the NAS should select an address for the user.
     *
     * @return true if the NAS should select the address
     */
    public boolean isNasSelected() {
        /*
        RFC is not clear on how address bytes should be ordered relative to the value indicator. However, javadoc for
         java's InetAddress class, getAddress() method indicates that network byte order is used and hence the
         highest order byte (the left most byte, 192, of a textual representation such as 192.168.10.20) is found in
         getAddress()[0]. Hence the implementation here for testing for 0xFFFFFFFE.
         */
        return (addr[0] == (byte) 255)
                && (addr[1] == (byte) 255)
                && (addr[2] == (byte) 255)
                && (addr[3] == (byte) 254);
    }

    /**
     * Indicates if the NAS should use the ip address indicated in this instance.
     *
     * @return true if the NAS should use the ip address in this instance.
     */
    public boolean isSpecified() {
        return (!this.isNasSelected()) && (!this.isUserNegotiated());
    }

    /**
     * Returns the Ip address.
     * @return the Ip address.
     */
    public byte[] getAddress() {
        return addr;
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
