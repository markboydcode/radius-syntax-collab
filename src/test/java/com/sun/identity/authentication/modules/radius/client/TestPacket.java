package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.Rfc2865Examples;
import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Created by markboyd on 6/19/14.
 */
public class TestPacket {

    @Test
    public void testSerializing_Rfc2865_7_1_example() {
        // what we should end up with
        String res =
                "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb " +
                        "98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d " +
                        "93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8 " +
                        "01 10 05 06 00 00 00 03";

        AccessRequest accessReq = new AccessRequest();
        accessReq.setIdentifier((short)0);
        accessReq.addAttribute(new UserNameAttribute("nemo"));

        String authenticatorBytes = "0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a";
        byte[] aBytes = Utils.toByteArray(authenticatorBytes);
        RequestAuthenticator authenticator = new RequestAuthenticator(aBytes);
        accessReq.setAuthenticator(authenticator);

        accessReq.addAttribute(new UserPasswordAttribute(authenticator, Rfc2865Examples.secret, Rfc2865Examples.password));
        try {
            accessReq.addAttribute(new NASIPAddressAttribute(InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, 16})));
        } catch (UnknownHostException e) {
            e.printStackTrace(); // ignore since it won't happen given valid address
        }
        accessReq.addAttribute(new NASPortAttribute(3));
        byte[] bytes = accessReq.getData();
        ByteBuffer pktBfr = ByteBuffer.wrap(bytes);
        String spaceHex = Utils.toSpacedHex(pktBfr);
        Assert.assertEquals(spaceHex, res, "output sequence of AccessRequest should have matched");
    }

    @Test
    public void testSerializing_Rfc2865_7_3_reject_example() throws IOException {
        // what we should end up with
        String res = "03 03 00 14 a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0";

        ByteBuffer bfr = Utils.toBuffer(res);
        Packet p = PacketFactory.toPacket(bfr);
        Assert.assertEquals(p.getType(), PacketType.ACCESS_REJECT, "should be reject packet");
        Assert.assertEquals(p.getIdentifier(), 3, "identifier should be 3");
        Assert.assertNotNull(p.getAuthenticator(), "authenticator should be found");
        byte[] authb = p.getAuthenticator().getData();
        String authHex = Utils.toSpacedHex(ByteBuffer.wrap(authb));
        Assert.assertEquals(authHex, "a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0", "auth bytes should match those from wire format");
    }

    @Test
    public void testSerializing_Rfc2865_7_3_reject_example_createServerPacket() throws IOException {
        // what we should end up with
        String res = "03 03 00 14 a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0";

        byte[] bytes = Utils.toByteArray(res);
        Packet p = PacketFactory.toPacket(bytes);
        Assert.assertEquals(p.getType(), PacketType.ACCESS_REJECT, "should be reject packet");
        Assert.assertEquals(p.getIdentifier(), 3, "identifier should be 3");
        Assert.assertNotNull(p.getAuthenticator(), "authenticator should be found");
        byte[] authb = p.getAuthenticator().getData();
        String authHex = Utils.toSpacedHex(ByteBuffer.wrap(authb));
        Assert.assertEquals(authHex, "a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0", "auth bytes should match those from wire format");
    }

    @Test
    public void testSerializing_Rfc2865_7_3_reject_example_createServerPacket_w_msg() throws IOException {
        // what we should end up with
        String res = "03 03 00 1b a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0 12 07 68 65 6c 6c 6f";

        byte[] bytes = Utils.toByteArray(res);
        Packet p = PacketFactory.toPacket(bytes);
        Assert.assertEquals(p.getType(), PacketType.ACCESS_REJECT, "should be reject packet");
        Assert.assertEquals(p.getIdentifier(), 3, "identifier should be 3");
        Assert.assertNotNull(p.getAuthenticator(), "authenticator should be found");
        byte[] authb = p.getAuthenticator().getData();
        String authHex = Utils.toSpacedHex(ByteBuffer.wrap(authb));
        Assert.assertEquals(authHex, "a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0", "auth bytes should match those from wire format");
        Assert.assertNotNull(p.getAttributeSet(), "should have attribute set");
        Assert.assertEquals(p.getAttributeSet().size(), 1, "should be one attribute");
        Attribute a = p.getAttributeAt(0);
        Assert.assertEquals(a.getType(), AttributeType.REPLY_MESSAGE.getTypeCode(), "should be a reply message");
        ReplyMessageAttribute r = (ReplyMessageAttribute) a;
        Assert.assertEquals(r.getString(), "hello", "message should be 'hello'");
    }

    @Test
    public void testSerializing_of_reject() throws IOException {
        // what we should end up with
        String res = "03 03 00 1b a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0 12 07 68 65 6c 6c 6f";

        byte[] bytes = Utils.toByteArray(res);
        Packet p = PacketFactory.toPacket(bytes);
        byte[] data = p.getData();
        String hex = Utils.toSpacedHex(ByteBuffer.wrap(data));

        Assert.assertEquals(hex, res, "serialized form should match original");
    }
}
