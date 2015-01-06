package com.sun.identity.authentication.modules.radius;

import java.util.Map;
import java.util.TreeMap;

/**
 * Attribute types corresponding to attribute type codes defined in rfc 2865 and extension RFCs.
 *
 * Created by markboyd on 6/19/14.
 */
public enum AttributeType {
    USER_NAME(1),
    USER_PASSWORD(2),
    CHAP_PASSWORD(3),
    NAS_IP_ADDRESS(4), // see section 5.4 of rfc 2865
    NAS_PORT(5),
    SERVICE_TYPE(6),
    FRAMED_PROTOCOL(7),
    FRAMED_IP_ADDRESS(8),
    FRAMED_IP_NETMASK(9),
    FRAMED_ROUTING(10),
    FILTER_ID(11),
    FRAMED_MTU(12),
    FRAMED_COMPRESSION(13),
    LOGIN_IP_HOST(14),
    LOGIN_SERVICE(15),
    LOGIN_TCP_PORT(16),
    // 17 HAS NOT BEEN ASSIGNED
    REPLY_MESSAGE(18),
    CALLBACK_NUMBER(19),
    CALLBACK_ID(20),
    // 21 HAS NOT BEEN ASSIGNED
    FRAMED_ROUTE(22),
    FRAMED_IPX_NETWORK(23),
    STATE(24),
    NAS_CLASS(25),
    VENDOR_SPECIFIC(26),
    SESSION_TIMEOUT(27),
    IDLE_TIMEOUT(28),
    TERMINATION_ACTION(29),
    CALLER_STATION_ID(30),
    CALLING_STATION_ID(31),
    NAS_IDENTIFIER(32),
    PROXY_STATE(33),
    LOGIN_LAT_SERVICE(34),
    LOGIN_LAT_NODE(35),
    LOGIN_LAT_GROUP(36),
    FRAMED_APPLETALK_LINK(37),
    FRAMED_APPLETALK_NETWORK(38),
    FRAMED_APPLETALK_ZONE(39),
    // 40-59 HAS NOT BEEN ASSIGNED
    CHAP_CHALLENGE(60),
    NAS_PORT_TYPE(61),
    PORT_LIMIT(62),
    LOGIN_LAT_PORT(63);

    private static Map<Integer, AttributeType> atts;

    /**
     * The attribute type code from rfc 2865 et al.
     */
    private final int typeCode;

    AttributeType(int typeCode) {
        this.typeCode = typeCode;
        addToIndex(this);
    }

    private void addToIndex(AttributeType att) {
        if (atts == null) {
            atts = new TreeMap<Integer, AttributeType>();
        }
        atts.put(att.typeCode, att);
    }

    public static final AttributeType getType(int typeCode) {
        return atts.get(typeCode);
    }

    /**
     * Get the attribute type code as defined in rfc 2865 or extension RFCs.
     *
     * @return
     */
    public int getTypeCode() {
        return typeCode;
    }

}
