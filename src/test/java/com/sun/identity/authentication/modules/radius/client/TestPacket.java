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
 * Copyright 2015 LDS
 */
package com.sun.identity.authentication.modules.radius.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.Rfc2865Examples;
import com.sun.identity.authentication.modules.radius.Utils;

/**
 * Created by markboyd on 6/19/14.
 */
public class TestPacket {

    /**
     * Test to ensure conformity with <a href="https://tools.ietf.org/html/rfc2865#section-7.1">IETF RFC 2865 section
     * 7.1</a>
     */
    @Test
    public void testSerializingRfc2865Section7dot1Example() {
        // what we should end up with
        String res = "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb "
                + "98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d "
                + "93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8 " + "01 10 05 06 00 00 00 03";

        AccessRequest accessReq = new AccessRequest();
        accessReq.setIdentifier((short) 0);
        accessReq.addAttribute(new UserNameAttribute("nemo"));

        String authenticatorBytes = "0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a";
        byte[] aBytes = Utils.toByteArray(authenticatorBytes);
        RequestAuthenticator authenticator = new RequestAuthenticator(aBytes);
        accessReq.setAuthenticator(authenticator);

        accessReq.addAttribute(new UserPasswordAttribute(authenticator, Rfc2865Examples.secret,
                Rfc2865Examples.password));
        try {
            InetAddress address = InetAddress.getByAddress(new byte[] { (byte) 192, (byte) 168, 1, 16 });
            accessReq.addAttribute(new NASIPAddressAttribute(address));
        } catch (UnknownHostException e) {
            e.printStackTrace(); // ignore since it won't happen given valid address
        }
        accessReq.addAttribute(new NASPortAttribute(3));
        byte[] bytes = accessReq.getData();
        ByteBuffer pktBfr = ByteBuffer.wrap(bytes);
        String spaceHex = Utils.toSpacedHex(pktBfr);
        Assert.assertEquals(spaceHex, res, "output sequence of AccessRequest should have matched");
    }

    /**
     * Test to ensure conformity with <a href="https://tools.ietf.org/html/rfc2865#section-7.3">IETF RFC 2865 section
     * 7.3</a>
     *
     * @throws IOException
     */
    @Test
    public void testSerializingRfc2865Section7dot3RejectExample() throws IOException {
        // what we should end up with
        String res = "03 03 00 14 a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0";

        ByteBuffer bfr = Utils.toBuffer(res);
        Packet p = PacketFactory.toPacket(bfr);
        Assert.assertEquals(p.getType(), PacketType.ACCESS_REJECT, "should be reject packet");
        Assert.assertEquals(p.getIdentifier(), 3, "identifier should be 3");
        Assert.assertNotNull(p.getAuthenticator(), "authenticator should be found");
        byte[] authb = p.getAuthenticator().getData();
        String authHex = Utils.toSpacedHex(ByteBuffer.wrap(authb));
        Assert.assertEquals(authHex, "a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0",
                "auth bytes should match those from wire format");
    }

    /**
     * Test to ensure conformity with <a href="https://tools.ietf.org/html/rfc2865#section-7.3">IETF RFC 2865 section
     * 7.3</a>
     *
     * @throws IOException
     */
    @Test
    public void testSerializingRfc2865Sec7dot3RejectExampleCreateServerPacketWithMsg() throws IOException {
        // what we should end up with
        String res = "03 03 00 1b a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0 12 07 68 65 6c 6c 6f";

        byte[] bytes = Utils.toByteArray(res);
        Packet p = PacketFactory.toPacket(bytes);
        Assert.assertEquals(p.getType(), PacketType.ACCESS_REJECT, "should be reject packet");
        Assert.assertEquals(p.getIdentifier(), 3, "identifier should be 3");
        Assert.assertNotNull(p.getAuthenticator(), "authenticator should be found");
        byte[] authb = p.getAuthenticator().getData();
        String authHex = Utils.toSpacedHex(ByteBuffer.wrap(authb));
        Assert.assertEquals(authHex, "a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0",
                "auth bytes should match those from wire format");
        Assert.assertNotNull(p.getAttributeSet(), "should have attribute set");
        Assert.assertEquals(p.getAttributeSet().size(), 1, "should be one attribute");
        Attribute a = p.getAttributeAt(0);
        Assert.assertEquals(a.getType(), AttributeType.REPLY_MESSAGE.getTypeCode(), "should be a reply message");
        ReplyMessageAttribute r = (ReplyMessageAttribute) a;
        Assert.assertEquals(r.getString(), "hello", "message should be 'hello'");
    }

    /**
     * Test the serialization.
     *
     * @throws IOException
     */
    @Test
    public void testSerializingOfReject() throws IOException {
        // what we should end up with
        String res = "03 03 00 1b a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0 12 07 68 65 6c 6c 6f";

        byte[] bytes = Utils.toByteArray(res);
        Packet p = PacketFactory.toPacket(bytes);
        byte[] data = p.getData();
        String hex = Utils.toSpacedHex(ByteBuffer.wrap(data));

        Assert.assertEquals(hex, res, "serialized form should match original");
    }
}
