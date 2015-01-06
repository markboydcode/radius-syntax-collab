package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

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
