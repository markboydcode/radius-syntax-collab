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

import java.nio.charset.Charset;

/**
 * Class representing the structure of the CHAP-Password attribute as specified in section 5.3 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes. This attribute is only included in access-requests.
 */
public class CHAPPasswordAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;
    /**
     * The chap identifier code from the user's CHAP response.
     */
    private int ident = 0;

    /**
     * The response value provided by a PPP Challenge-Handshake Authentication Protocol (CHAP) user in response to
     * the challenge.
     */
    private String password = null;

    /**
     * Construct a new instance from the password string and chap identifier code from the CHAP response. RFC 2865
     * isn't very clear on the "password" value other than saying it is  16 octets in length. For clarity we must
     * read RFC 1994 section 4.1 that indicates the CHAP-Password hold a 16 byte hash value created as noted in the RFC.
     * Therefore, we ensure that the resulting bytes are 16 in length and if less we pad them with 0 values.
     * Additionally, the integer value should be less than 256 since it gets truncated to a single octet.
     *
     * @param password the CHAP response from the user
     * @param identifier the CHAP identifier
     */
    public CHAPPasswordAttribute(String password, int identifier) {
        this.password = password;
        this.ident = identifier;
        octets = new byte[19];
        byte[] s = this.password.getBytes(Charset.forName("utf-8"));

        // this is not part of rfc 2865 but added to for consistency rather than leaving random values in the unused
        // portion of the array and to prevent an array index out of bounds exception
        if (s.length < 16) {
            byte[] s2 = new byte[16];
            System.arraycopy(s, 0, s2, 0, s.length);
            for (int i = s.length; i < 16; i++) {
                s2[i] = 0;
            }
            s = s2;
        }
        octets[0] = CHAP_PASSWORD;
        octets[1] = 19;
        octets[2] = (byte) this.ident;
        System.arraycopy(s, 0, octets, 3, 16);
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public CHAPPasswordAttribute(byte[] octets) {
        super(CHAP_PASSWORD);
        ident = octets[2];
        password = new String(octets, 3, 16, Charset.forName("utf-8"));
        this.octets = octets;
    }

    /**
     * Returns the chap identifier code from the user's CHAP response.
     * @return the identifier
     */
    public int getIdentifier() {
        return ident;
    }

    /**
     * Returns the CHAP password.
     * @return the password.
     */
    public String getPassword() {
        return password;
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

        return new StringBuilder().append(ident).append(", *******").toString(); // we don't log passwords
    }
}
