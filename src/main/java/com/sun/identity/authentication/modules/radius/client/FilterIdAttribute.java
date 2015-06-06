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
 * Class representing the structure of the Filter-Id attribute as specified in section 5.11 of RFC 2865 and
 * able to be instantiated from the on-the-wire bytes or from its text value.
 */
public class FilterIdAttribute extends Attribute {
    /**
     * The on-the-wire byte representation of the attribute.
     */
    private byte[] octets = null;

    /**
     * The filter id string.
     */
    private String filterId = null;

    /**
     * Constructs a new instance from the filter string to be embedded. Since attribute fields in a radius packet are
     * limited to 256 octets in length the string will be truncated accordingly if it exceeds 254 bytes due to the
     * preceding attriute type code octet and attribute length octets being included in the overall attribute length.
     *
     * @param filter the filter id
     */
    public FilterIdAttribute(String filter) {
        super(FILTER_ID);
        byte[] s = filter.getBytes();
        if (s.length > 253) {
            octets = new byte[255];
            octets[0] = (byte) super.getType();
            octets[1] = (byte) 255; // max length
            System.arraycopy(s, 0, octets, 2, 253);
            filterId = new String(octets, 2, 253);
        } else {
            octets = new byte[s.length + 2];
            octets[0] = (byte) super.getType();
            octets[1] = (byte) (s.length + 2);
            System.arraycopy(s, 0, octets, 2, s.length);
            filterId = filter;
        }
    }

    /**
     * Constructs a new instance from the on-the-wire bytes for this attribute including the prefixing attribute-type
     * code octet and length octet.
     *
     * @param octets the on-the-wire bytes from which to construct this instance
     */
    public FilterIdAttribute(byte[] octets) {
        super(FILTER_ID);
        this.filterId = new String(octets, 2, octets.length - 2);
        this.octets = octets;
    }

    /**
     * Returns the filter id.
     * @return the filter id.
     */
    public String getFilterId() {
        return filterId;
    }

    /**
     * Returns the on-the-wire bytes used to construct this instance.
     *
     * @return the on-the-wire byte representation of this attribute.
     */
    public byte[] getValue() {
        return this.octets;
    }

    /**
     * Used by super class to log the attribute's contents when packet logging is enabled.
     *
     * @return content representation for traffic logging
     */
    public String toStringImpl() {

        return filterId;
    }
}
