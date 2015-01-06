package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.Rfc2865Examples;
import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by markboyd on 6/19/14.
 */
public class TestUserPasswordAttribute {

    @Test
    public void testEncDec() throws IOException {
        String spaceHexAuthnctr = "0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a"; // from rfc 2865 ex 7.1
        RequestAuthenticator authnctr = new RequestAuthenticator(Utils.toByteArray(spaceHexAuthnctr));
        UserPasswordAttribute upa = new UserPasswordAttribute(authnctr, Rfc2865Examples.secret, Rfc2865Examples.password);
        byte[] data = upa.getData();
        System.out.println("on-the-wire attribute sequence: " + Utils.toSpacedHex(ByteBuffer.wrap(data)));

        // now reverse and get password back out
        UserPasswordAttribute upa2 = new UserPasswordAttribute(data);
        String pwd = upa2.extractPassword(authnctr, Rfc2865Examples.secret);
        Assert.assertEquals(pwd, Rfc2865Examples.password, "passwords should be recoverable");
    }

    @Test
    public void testLongerPwd() throws IOException {
        String spaceHexAuthnctr = "4d 83 19 3b 80 31 9b b0 43 a5 b6 94 a5 12 43 5b";
        RequestAuthenticator authnctr = new RequestAuthenticator(Utils.toByteArray(spaceHexAuthnctr));
        String wireSeq = "02 12 f0 82 69 17 e4 ef 18 e5 44 e1 53 c0 06 b0 43 df"; // depends on client secret and authntctr
        byte[] wireBytes = Utils.toByteArray(wireSeq);
        String clientSecret = "don't tell";
        UserPasswordAttribute upa = new UserPasswordAttribute(wireBytes);
        String pwd = upa.extractPassword(authnctr, clientSecret);
        Assert.assertEquals(pwd, "secret", "passwords should be 'secret'");
    }
}
