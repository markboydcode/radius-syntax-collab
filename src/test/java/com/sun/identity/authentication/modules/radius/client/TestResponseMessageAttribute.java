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
import java.nio.ByteBuffer;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.Utils;

/**
 * Created by markboyd on 6/20/14.
 */
public class TestResponseMessageAttribute {

    @Test
    public void test() throws IOException {
        ReplyMessageAttribute r = new ReplyMessageAttribute("hello");
        Assert.assertEquals(r.getType(), AttributeType.REPLY_MESSAGE.getTypeCode(), "should be a reply message");
        Assert.assertEquals(r.getString(), "hello", "message should be 'hello'");
        byte[] data = r.getData();
        String hex = Utils.toSpacedHex(ByteBuffer.wrap(data));
        System.out.println("data: " + hex);
        Assert.assertEquals(hex, "12 07 68 65 6c 6c 6f", "should have proper wire format");
    }
}
