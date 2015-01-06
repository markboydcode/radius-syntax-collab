package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.PacketType;
import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Unit tests for PacketFactory.
 *
 * Created by markboyd on 6/19/14.
 */
public class TestPacketFactory {

    @Test
    public void testRfc2865_7_1_example() throws UnknownHostException {
        String hex =
                "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb" +
                "98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d" +
                "93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8" +
                "01 10 05 06 00 00 00 03";

        ByteBuffer bfr = Utils.toBuffer(hex);
        dumpBfr(bfr);
        Packet pkt = PacketFactory.toPacket(bfr);
        Assert.assertNotNull(pkt.getAuthenticator(), "authenticator should be defined");
        Assert.assertEquals(pkt.getType(), PacketType.ACCESS_REQUEST, "Incorrect type code");
        Assert.assertEquals(pkt.getIdentifier(), 0, "packet identifier should have been 0");
        Assert.assertEquals(pkt.getAttributeSet().size(), 4, "packet attributes contained");

        Assert.assertEquals(pkt.getAttributeAt(0).getClass().getSimpleName(),
                UserNameAttribute.class.getSimpleName(), "0 attribute");
        Assert.assertEquals(((UserNameAttribute)pkt.getAttributeAt(0)).getName(), "nemo","user name");

        Assert.assertEquals(pkt.getAttributeAt(1).getClass().getSimpleName(),
                UserPasswordAttribute.class.getSimpleName(), "1 attribute");

        Assert.assertEquals(pkt.getAttributeAt(2).getClass().getSimpleName(),
                NASIPAddressAttribute.class.getSimpleName(), "2 attribute");
        Assert.assertEquals(((NASIPAddressAttribute) pkt.getAttributeAt(2)).getIpAddress(),
                InetAddress.getByAddress(new byte[]{(byte)192, (byte)168,1,16}), "NAS IP address");

        Assert.assertEquals(pkt.getAttributeAt(3).getClass().getSimpleName(),
                NASPortAttribute.class.getSimpleName(), "3 attribute");
        Assert.assertEquals(((NASPortAttribute)pkt.getAttributeAt(3)).getPort(), 3,"NAS port");

    }

    /**
     * dumps to std out in sets of 16 hex bytes separated by spaces
     * and prefixed with '0' for bytes having value less than 0x10.
     * The buffer is returned as was meaning ready to read from the
     * same point as when it was passed to this method.
     *
     * @param bfr
     */
    private void dumpBfr(ByteBuffer bfr) {
        System.out.println("Packet contents: ");

        bfr.mark();
        int i = 0;

        for(;bfr.hasRemaining();) {
            if (i == 16) {
                System.out.println();
                i=0;
            }
            i++;
            byte b = bfr.get();
            int j = ((int) b) & 0xFF; // trim off sign-extending bits
            String bt = Integer.toHexString(j);
            if (bt.length() == 1) { // prefix single chars with '0'
                bt = "0" + bt;
            }

            System.out.print(bt + " ");

        }
        bfr.reset();
        System.out.println();
    }

    @Test
    private void test_UserName_Att() {
        String hex = "01 06 6e 65 6d 6f";
        ByteBuffer bfr = Utils.toBuffer(hex);
        Attribute att = PacketFactory.nextAttribute(bfr);
        Assert.assertEquals(att.getClass().getSimpleName(), UserNameAttribute.class.getSimpleName(), "wrong attribute class instantiated");
        UserNameAttribute una = (UserNameAttribute) att;
        Assert.assertEquals(una.getName(), "nemo");
    }

    @Test
    private void testBytes() {
        byte b = 0x00;
        byte[] bytes = new byte[1];

        for(int i=0; i<256; i++) {
            bytes[0] = b;
            int j = ((int) b) & 0xFF;
            short k = (short) j;

            System.out.println((b>0 ? " " : "") + b + " " + Utils.toSpacedHex(ByteBuffer.wrap(bytes)) + " " + j + " " + k + " - " + (bytes[0] & 0xFF));
            b++;
        }
    }
}