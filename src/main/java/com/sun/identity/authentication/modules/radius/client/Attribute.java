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

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Legacy class from before enum types were supported and holder of constants of all defined radius attribute type
 * codes outlined in RFC 2865. If support for new types is added we should just be able to add them to the
 * {@link com.sun.identity.authentication.modules.radius.AttributeType} class without adding them here.
 */
public abstract class Attribute {
    /**
     * Represents all unknown type codes. This is an artifact of this library and not of any RFC.
     */
    public static final int UNRECOGNIZED = 0;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the User-Name field as
     * specified in section 5.1 of RFC 2865.
     */
    public static final int USER_NAME = 1;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the User-Password field as
     * specified in section 5.2 of RFC 2865.
     */
    public static final int USER_PASSWORD = 2;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the CHAP-Password field as
     * specified in section 5.3 of RFC 2865.
     */
    public static final int CHAP_PASSWORD = 3;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the NAS-IP-Address field as
     * specified in section 5.4 of RFC 2865.
     */
    public static final int NAS_IP_ADDRESS = 4;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the NAS-Port field as
     * specified in section 5.5 of RFC 2865.
     */
    public static final int NAS_PORT = 5;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Service-Type field as
     * specified in section 5.6 of RFC 2865.
     */
    public static final int SERVICE_TYPE = 6;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-Protocol field as
     * specified in section 5.7 of RFC 2865.
     */
    public static final int FRAMED_PROTOCOL = 7;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-IP-Address field as
     * specified in section 5.8 of RFC 2865.
     */
    public static final int FRAMED_IP_ADDRESS = 8;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-IP-Netmask field as
     * specified in section 5.9 of RFC 2865.
     */
    public static final int FRAMED_IP_NETMASK = 9;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-Routing field as
     * specified in section 5.10 of RFC 2865.
     */
    public static final int FRAMED_ROUTING = 10;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Filter-Id field as
     * specified in section 5.11 of RFC 2865.
     */
    public static final int FILTER_ID = 11;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-MTU field as
     * specified in section 5.12 of RFC 2865.
     */
    public static final int FRAMED_MTU = 12;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-Compression field as
     * specified in section 5.13 of RFC 2865.
     */
    public static final int FRAMED_COMPRESSION = 13;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-IP-Host field as
     * specified in section 5.14 of RFC 2865.
     */
    public static final int LOGIN_IP_HOST = 14;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-Service field as
     * specified in section 5.15 of RFC 2865.
     */
    public static final int LOGIN_SERVICE = 15;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-TCP-Port field as
     * specified in section 5.16 of RFC 2865.
     */
    public static final int LOGIN_TCP_PORT = 16;

    // 17 HAS NOT BEEN ASSIGNED

    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Reply-Message field as
     * specified in section 5.18 of RFC 2865.
     */
    public static final int REPLY_MESSAGE = 18;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Callback-Number field as
     * specified in section 5.19 of RFC 2865.
     */
    public static final int CALLBACK_NUMBER = 19;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Callback-Id field as
     * specified in section 5.20 of RFC 2865.
     */
    public static final int CALLBACK_ID = 20;

    // 21 HAS NOT BEEN ASSIGNED

    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-Route field as
     * specified in section 5.22 of RFC 2865.
     */
    public static final int FRAMED_ROUTE = 22;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-IPX-Network field as
     * specified in section 5.23 of RFC 2865.
     */
    public static final int FRAMED_IPX_NETWORK = 23;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the State field as
     * specified in section 5.24 of RFC 2865.
     */
    public static final int STATE = 24;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Class field as
     * specified in section 5.25 of RFC 2865.
     */
    public static final int NAS_CLASS = 25;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Vendor-Specific field as
     * specified in section 5.26 of RFC 2865.
     */
    public static final int VENDOR_SPECIFIC = 26;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Session-Timeout field as
     * specified in section 5.27 of RFC 2865.
     */
    public static final int SESSION_TIMEOUT = 27;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Idle-Timeout field as
     * specified in section 5.28 of RFC 2865.
     */
    public static final int IDLE_TIMEOUT = 28;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Termination-Action field as
     * specified in section 5.29 of RFC 2865.
     */
    public static final int TERMINATION_ACTION = 29;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Called-Station-Id field as
     * specified in section 5.30 of RFC 2865.
     */
    public static final int CALLER_STATION_ID = 30;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Calling-Station-Id field as
     * specified in section 5.31 of RFC 2865.
     */
    public static final int CALLING_STATION_ID = 31;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the NAS-Identifier field as
     * specified in section 5.32 of RFC 2865.
     */
    public static final int NAS_IDENTIFIER = 32;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Proxy-State field as
     * specified in section 5.33 of RFC 2865.
     */
    public static final int PROXY_STATE = 33;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-LAT-Service field as
     * specified in section 5.34 of RFC 2865.
     */
    public static final int LOGIN_LAT_SERVICE = 34;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-LAT-Node field as
     * specified in section 5.35 of RFC 2865.
     */
    public static final int LOGIN_LAT_NODE = 35;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-LAT-Group field as
     * specified in section 5.36 of RFC 2865.
     */
    public static final int LOGIN_LAT_GROUP = 36;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-AppleTalk-Link
     * field as specified in section 5.37 of RFC 2865.
     */
    public static final int FRAMED_APPLETALK_LINK = 37;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-AppleTalk-Network
     * field as specified in section 5.38 of RFC 2865.
     */
    public static final int FRAMED_APPLETALK_NETWORK = 38;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Framed-AppleTalk-Zone
     * field as specified in section 5.39 of RFC 2865.
     */
    public static final int FRAMED_APPLETALK_ZONE = 39;

    // 40-59 HAS NOT BEEN ASSIGNED

    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the CHAP-Challenge field as
     * specified in section 5.40 of RFC 2865.
     */
    public static final int CHAP_CHALLENGE = 60;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the NAS-Port-Type field as
     * specified in section 5.41 of RFC 2865.
     */
    public static final int NAS_PORT_TYPE = 61;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Port-Limit field as
     * specified in section 5.42 of RFC 2865.
     */
    public static final int PORT_LIMIT = 62;
    /**
     * The byte value for the 'type' field of the wire protocol indicating the field is the Login-LAT-Port field as
     * specified in section 5.43 of RFC 2865.
     */
    public static final int LOGIN_LAT_PORT = 63;


    /**
    On the wire format of an attribute is one octet of type, one octet of length, and the remaining octets of value.
    this means that the maximum length of the value octets is 255 - 2 (one for the type and one for the length octets)
    for a maximum of 253.
     */
    public static final int MAX_ATTRIBUTE_VALUE_LENGTH = 253; // since attribute

    /**
     * The type of this attribute instance.
     */
    protected int _t = 0;

    /**
     * Consturcts an instance but without an associated type code. It appears that much of the legacy code uses this
     * constructor and then immediately assigns the value of _t which is totally rediculous. That code should call
     * the other constructor and not set _t directly.
     *
     * @TODO remove this constructor and replace its use as noted.
     */
    public Attribute() {
    }

    /**
     * Constructor used by subclasses and instantiating an instance to include its type code.
     * @param t the attribute type code
     */
    public Attribute(int t) {
        _t = t;
    }

    /**
     * Returns the type code of the attribute.
     *
     * @return code indicative of the type of radius attribute.
     */
    public int getType() {
        return _t;
    }

    /**
     * Return an array of octets representing the format of a given attribute on-the-wire as defined by
     * RFC 2865 or an extension RFC but excluding the three on-the-wire bytes representing the prefixed type octet and
     * two length octets defined in RFC 2865.
     *
     * @return the on-the-wire octet representation of this attribute
     * @throws java.io.IOException if unable to extract an attribute instance's on-the-wire octets.
     */
    public abstract byte[] getValue()
            throws IOException;

    /**
     * Returns a byte array with on-the-wire attribute format delegating to getValue() for attribute
     * specific serialization of contained field values.
     *
     * @return the on-the-wire byte representation of this attribute including preceding type and length octets.
     * @throws java.io.IOException if there are problems instantiating a {@link java.io.ByteArrayOutputStream}
     */
    public byte[] getData()
            throws IOException {
        ByteArrayOutputStream attrOS = new ByteArrayOutputStream();
        attrOS.write(_t); // type
        byte[] value = getValue();
        attrOS.write(value.length + 2); // length
        attrOS.write(value);

        return attrOS.toByteArray();
    }

    /**
     * Shows a String representation of the contents of a given field. Used for logging packet traffic.
     * @return the representation of the attribute when traffic logging is enabled
     */
    public String toString() {
        AttributeType t = AttributeType.getType(this.getType());
        StringBuilder s = new StringBuilder();

        if (t == null) {
            try {
                s.append("UNKNOWN TYPE : ")
                        .append(_t)
                        .append(" ")
                        .append(Utils.toHexAndPrintableChars(this.getData())).toString();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            s.append(t);
        }
        String content = this.toStringImpl();

        if (!"".equals(content)) {
            s.append(" : ").append(content);
        }
        return s.toString();
    }

    /**
     * Method expected to be overridden by subclasses to append detail beyond attribute type name. Used by logging to
     * protray attribute field structure when logging packet traffic if special handling is required for a given
     * field distinct from that provided by the super class.
     *
     * @return the string representation of this attribute which is an empty string by default.
     */
    public String toStringImpl() {
        return "";
    }

}
