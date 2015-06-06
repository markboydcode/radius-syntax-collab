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
 * Tests for the FramedAppleTalkNetworkAttribute class.
 *
 * Created by markboyd on 6/05/15.
 */
public class TestFramedAppleTalkNetworkAttribute {

    @Test
    public void testUnnumbered() throws IOException {
        FramedAppleTalkNetworkAttribute a = new FramedAppleTalkNetworkAttribute(0);
        Assert.assertTrue(a.isNasAssigned(), "0 should result in NAS assigned network");
        byte[] bytes = a.getValue();
        Assert.assertEquals(bytes[0], Attribute.FRAMED_APPLETALK_NETWORK);
        Assert.assertEquals(bytes[1], 6);
        Assert.assertEquals(a.getNetworkNumber(), 0);
    }

    @Test
    public void testMaxNumbered() throws IOException {
        FramedAppleTalkNetworkAttribute a = new FramedAppleTalkNetworkAttribute(65535);
        Assert.assertEquals(a.getNetworkNumber(), 65535);
        Assert.assertFalse(a.isNasAssigned(), ">0 should result in an assigned port");
        byte[] bytes = a.getValue();
        Assert.assertEquals(bytes[0], Attribute.FRAMED_APPLETALK_NETWORK);
        Assert.assertEquals(bytes[1], 6);
        Assert.assertEquals(bytes[2], 0);
        Assert.assertEquals(bytes[3], 0);
        Assert.assertEquals(bytes[4], (byte) 255);
        Assert.assertEquals(bytes[5], (byte) 255);
    }

    @Test
    public void testMaxFromRawBytes() throws IOException {
        byte[] raw = new byte[] {38, 6, 0, 0, (byte) 255, (byte) 255};
        FramedAppleTalkNetworkAttribute a = new FramedAppleTalkNetworkAttribute(raw);
        Assert.assertEquals(a.getType(), Attribute.FRAMED_APPLETALK_NETWORK);
        Assert.assertEquals(a.getNetworkNumber(), 65535);
        Assert.assertEquals(a.isNasAssigned(), false);
    }

    @Test
    public void testMinFromRawBytes() throws IOException {
        byte[] raw = new byte[] {38, 6, 0, 0, 0, 1};
        FramedAppleTalkNetworkAttribute a = new FramedAppleTalkNetworkAttribute(raw);
        Assert.assertEquals(a.getType(), Attribute.FRAMED_APPLETALK_NETWORK);
        Assert.assertEquals(a.getNetworkNumber(), 1);
        Assert.assertEquals(a.isNasAssigned(), false);
    }

    @Test
    public void testUnnumberedFromRawBytes() throws IOException {
        byte[] raw = new byte[] {38, 6, 0, 0, 0, 0};
        FramedAppleTalkNetworkAttribute a = new FramedAppleTalkNetworkAttribute(raw);
        Assert.assertEquals(a.getType(), Attribute.FRAMED_APPLETALK_NETWORK);
        Assert.assertEquals(a.getNetworkNumber(), 0);
        Assert.assertEquals(a.isNasAssigned(), true);
    }
}
