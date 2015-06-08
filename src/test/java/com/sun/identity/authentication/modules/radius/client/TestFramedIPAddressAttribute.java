package com.sun.identity.authentication.modules.radius.client;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Created by boydmr on 6/5/15.
 */
public class TestFramedIPAddressAttribute {

    @Test
    public void testUserNegotiated() {
        FramedIPAddressAttribute a = new FramedIPAddressAttribute(FramedIPAddressAttribute.Type.USER_NEGOTIATED, null);
        Assert.assertTrue(a.isUserNegotiated());
        Assert.assertFalse(a.isNasSelected());
        Assert.assertFalse(a.isSpecified());
    }

    @Test
    public void testIsNasSelected() {
        FramedIPAddressAttribute a = new FramedIPAddressAttribute(FramedIPAddressAttribute.Type.NAS_ASSIGNED, null);
        Assert.assertFalse(a.isUserNegotiated());
        Assert.assertTrue(a.isNasSelected());
        Assert.assertFalse(a.isSpecified());
    }

    @Test
    public void testIsSpecified() {
        FramedIPAddressAttribute a = new FramedIPAddressAttribute(FramedIPAddressAttribute.Type.SPECIFIED,
                new byte[] {(byte)192, (byte)168, 1, 3});
        Assert.assertFalse(a.isUserNegotiated());
        Assert.assertFalse(a.isNasSelected());
        Assert.assertTrue(a.isSpecified());
        Assert.assertEquals(a.getAddress()[0], (byte) 192);
        Assert.assertEquals(a.getAddress()[1], (byte)168);
        Assert.assertEquals(a.getAddress()[2], (byte)1);
        Assert.assertEquals(a.getAddress()[3], (byte)3);
    }
}
