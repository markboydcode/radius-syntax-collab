package com.sun.identity.authentication.modules.radius;

import java.util.HashMap;
import java.util.Map;

/**
 * The packet types in RADIUS rfc 2865.
 *
 * Created by markboyd on 6/18/14.
 */
public enum PacketType {

    ACCESS_REQUEST(1),
    ACCESS_ACCEPT(2),
    ACCESS_REJECT(3),
    ACCOUNTING_REQUEST(4),
    ACCOUNTING_RESPONSE(5),
    ACCESS_CHALLENGE(11),
    RESERVED(255);

    /**
     * The integer code indicating the type of the packet.
     */
    private int type;

    /**
     * Lookup map by type code.
     */
    private static Map<Integer, PacketType> types;

    /**
     * Create a PacketType associated with the given code from rfc 2865.
     * @param type
     */
    PacketType(int type) {
        this.type = type;
        addTypeToMap(this);
    }

    /**
     * Builds the lookup map for use in getPacketType static method.
     * @param t
     */
    private void addTypeToMap(PacketType t) {
        if (types == null) {
            types = new HashMap<Integer, PacketType>();
        }
        types.put(t.getTypeCode(), t);
    }

    /**
     * Get the type code for a given PacketType.
     * @return
     */
    public int getTypeCode() {
        return type;
    }

    /**
     * Get the PacketType corresponding to a given code from an incoming packet.
     *
     * @param code
     * @return
     */
    public static final PacketType getPacketType(int code) {
        return types.get(code);
    }
}
