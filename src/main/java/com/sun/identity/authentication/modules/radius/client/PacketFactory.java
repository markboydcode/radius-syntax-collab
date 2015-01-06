/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: PacketFactory.java,v 1.2 2008/06/25 05:42:02 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.server.poc.RadiusListener;

import java.nio.ByteBuffer;

public class PacketFactory
{
	public static Packet toPacket(byte data[])
	{
        // for old byte array approach we may have a array longer than packet so trim ByteBuffer down to just
        // packet length to prevent attribute parsing below from running off the end of the packet and onto unrelated
        // octets. length is 3rd/4th octets in big endian, network byte order.
        int packetLen = data[3] & 0xFF;
        packetLen |= ((data[2] << 8) & 0xFF00);

        return toPacket(ByteBuffer.wrap(data, 0, packetLen));
	}

    /**
     * Translates a raw set of bytes from the wire format of rfc 2865 to our java objects.
     *
     * @param data ByteBuffer containing the data for the packet in on-the-wire-format.
     * @return
     */
    public static Packet toPacket(ByteBuffer data) {

        byte code = data.get(); // one octet packet type code field
        // one octet packet id field, convert to unsigned solely for presentation when logging so ids are all positive.
        short id = (short)(((int) data.get()) & 0xFF);
        short datalen = data.getShort(); // two octet packet length field (code, id, length, authenticator, and attribute fields)

        // ------ start of spooling for file
        // mark buffer here
        data.mark();

        // create array of datalen minus 3
        byte[] bytes = new byte[datalen - 3];

        // read packet off
        // TODO: write to file with name of 'R' + code + '.log"
        // reset buffer
        // ------ end of spooling for file

        // read 16 octet authenticator field
        byte[] authData = new byte[16];
        data.get(authData);

        PacketType type = PacketType.getPacketType(code);
        Packet pkt = null;

        switch (type) {
            case ACCESS_ACCEPT:
                pkt = new AccessAccept();
                pkt.setAuthenticator(new ResponseAuthenticator(authData));
                break;
            case ACCESS_CHALLENGE:
                pkt = new AccessChallenge();
                pkt.setAuthenticator(new ResponseAuthenticator(authData));
                break;
            case ACCESS_REJECT:
                pkt = new AccessReject();
                pkt.setAuthenticator(new ResponseAuthenticator(authData));
                break;
            case ACCESS_REQUEST:
                pkt = new AccessRequest();
                pkt.setAuthenticator(new RequestAuthenticator(authData));
                break;
//            case ACCOUNTING_REQUEST:
//                break;
//            case ACCOUNTING_RESPONSE:
//                break;
            default:
                System.out.println(RadiusListener.getTimeStampAsString() + "WARNING: Unhandled packet type: " + type);
                return null;
        }
        pkt.setIdentifier(id);

        // building attributes
        Attribute a = null;
         while ((a = PacketFactory.nextAttribute(data)) != null) {
            pkt.addAttribute(a);
        }
        return pkt;
    }

    /**
     * Reads the next attribute out of the buffer or null if there is no more content.
     *
     * @param bfr
     * @return
     */
    public static Attribute nextAttribute(ByteBuffer bfr) {
        // requires that ByteBuffer only contains a full radius packet and ends where the attributes end without
        // additional unrelated octets.
        if (! bfr.hasRemaining()) {
            return null;
        }
         /*
         existing AttributeFactory expects array containing octets only for a single attribute but including
         prefixed type octet and length octet. So we need to mark the start of the attribute's data, read off
         type and length to be able to pull its data off, then reset and pull the whole thing out or assemble
         an array with the prefixed values placed back in there.
          */
        bfr.mark(); // mark the start of the attribute's data chunk
        byte attType = bfr.get(); // pull off the type

        byte len = bfr.get(); // get its data length, byte is signed so we need to convert to unsigned byte
        int length = ((int) len) & 0xFF; // may have gotten sign extension so trim down to one byte

        // now reset and pull it out with the two prefixed octets
        byte[] attrData = new byte[length];
        bfr.reset(); // puts it back to just before the type indicator
        bfr.get(attrData); // reads the type, length, and payload

        return AttributeFactory.createAttribute(attrData);

    }
}
