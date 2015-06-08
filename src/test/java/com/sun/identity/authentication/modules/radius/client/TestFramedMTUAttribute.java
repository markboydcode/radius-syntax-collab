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

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

/**
 * Tests for the FramedAppleTalkLinkAttribute class.
 *
 * Created by markboyd on 6/05/15.
 */
public class TestFramedMTUAttribute {

    @Test
    public void testHighest() throws IOException {
        FramedMTUAttribute a = new FramedMTUAttribute(65535);
        Assert.assertEquals(a.getMtu(), 65535, "mtu should be 65535");
        byte[] bytes = a.getValue();
        Assert.assertEquals(bytes[0], Attribute.FRAMED_MTU);
        Assert.assertEquals(bytes[1], 6);

        FramedMTUAttribute b = new FramedMTUAttribute(bytes);
        Assert.assertEquals(b.getMtu(), 65535, "mtu created from octets should be 65535");
    }

    @Test
    public void testHighestFromOctets() throws IOException {
        FramedMTUAttribute a = new FramedMTUAttribute(new byte[] {Attribute.FRAMED_MTU, 6, 0, 0, (byte) 255, (byte)
                255});
        Assert.assertEquals(a.getMtu(), 65535, "mtu should be 65535");
    }

    @Test
    public void testLowest() throws IOException {
        FramedMTUAttribute a = new FramedMTUAttribute(64);
        Assert.assertEquals(a.getMtu(), 64, "mtu should be 64");
        byte[] bytes = a.getValue();
        Assert.assertEquals(bytes[0], Attribute.FRAMED_MTU);
        Assert.assertEquals(bytes[1], 6);

        FramedMTUAttribute b = new FramedMTUAttribute(bytes);
        Assert.assertEquals(b.getMtu(), 64, "mtu created from octets should be 64");
    }
    @Test
    public void testLowestFromOctets() throws IOException {
        FramedMTUAttribute a = new FramedMTUAttribute(new byte[] {Attribute.FRAMED_MTU, 6, 0, 0, 0, 64});
        Assert.assertEquals(a.getMtu(), 64, "mtu should be 64");
    }

}
