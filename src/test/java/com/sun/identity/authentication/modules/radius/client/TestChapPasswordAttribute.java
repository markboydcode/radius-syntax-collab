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

import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.Charset;

/**
 * Tests for the CHAPPasswordAttribute class.
 *
 * Created by markboyd on 6/19/14.
 */
public class TestChapPasswordAttribute {

    @Test
    public void testPaddingShortHash() throws IOException {
        CHAPPasswordAttribute a = new CHAPPasswordAttribute("challenge", 27);
        byte[] bytes = a.getValue();
        Assert.assertEquals(bytes[0], Attribute.CHAP_PASSWORD);
        Assert.assertEquals(bytes[1], 19);
        Assert.assertEquals(bytes[2], 27);
        Assert.assertNotEquals(new String(bytes, 3, 16, Charset.forName("utf-8")), "challenge");
        Assert.assertTrue(new String(bytes, 3, 16, Charset.forName("utf-8")).startsWith("challenge"));
    }

    @Test
    public void testValidHashLength() throws IOException {
        CHAPPasswordAttribute a = new CHAPPasswordAttribute("1234567890123456", 27);
        byte[] bytes = a.getValue();
        System.out.println("hAp0=" + Utils.toHexAndPrintableChars(bytes));
        Assert.assertEquals(bytes[0], Attribute.CHAP_PASSWORD);
        Assert.assertEquals(bytes[1], 19);
        Assert.assertEquals(bytes[2], 27);
        Assert.assertEquals(new String(bytes, 3, 16, Charset.forName("utf-8")), "1234567890123456");
    }


    @Test
    public void testFromRawBytes() throws IOException {
        byte[] raw = new byte[] {03, 19, 27, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54};
        System.out.println("hAp1=" + Utils.toHexAndPrintableChars(raw));
        CHAPPasswordAttribute a = new CHAPPasswordAttribute(raw);
        byte[] bytes = a.getValue();
        System.out.println("hAp2=" + Utils.toHexAndPrintableChars(bytes));
        Assert.assertEquals(bytes[0], Attribute.CHAP_PASSWORD);
        Assert.assertEquals(bytes[1], 19);
        Assert.assertEquals(bytes[2], 27);
        Assert.assertEquals(new String(bytes, 3, 16, Charset.forName("utf-8")), "1234567890123456");
    }
}
