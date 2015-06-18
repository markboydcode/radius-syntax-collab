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

import com.sun.identity.authentication.modules.radius.Rfc2865Examples;
import com.sun.identity.authentication.modules.radius.Utils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by markboyd on 6/19/14.
 */
public class TestUserPasswordAttribute {

    @Test
    public void testEncDec() throws IOException {
        String spaceHexAuthnctr = "0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a"; // from rfc 2865 ex 7.1
        RequestAuthenticator authnctr = new RequestAuthenticator(Utils.toByteArray(spaceHexAuthnctr));
        UserPasswordAttribute upa = new UserPasswordAttribute(authnctr, Rfc2865Examples.secret,
                Rfc2865Examples.password);
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
        String wireSeq = "02 12 f0 82 69 17 e4 ef 18 e5 44 e1 53 c0 06 b0 43 df"; // depends on client secret and
                                                                                  // authntctr
        byte[] wireBytes = Utils.toByteArray(wireSeq);
        String clientSecret = "don't tell";
        UserPasswordAttribute upa = new UserPasswordAttribute(wireBytes);
        String pwd = upa.extractPassword(authnctr, clientSecret);
        Assert.assertEquals(pwd, "secret", "passwords should be 'secret'");
    }

    SecureRandom rand = new SecureRandom();
    String secret = "my-secret";

    /**
     * Tests the first boundary incurrence meaning the password length is the same length as the 16 byte hash used for
     * XOR'ing.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     */
    @Test
    public void test15charPwd() throws NoSuchAlgorithmException, IOException {
        String pwd15 = "123456789_12345";
        SecureRandom rand = new SecureRandom();
        RequestAuthenticator ra = new RequestAuthenticator(rand, secret);
        UserPasswordAttribute upa = new UserPasswordAttribute(ra, secret, pwd15);
        byte[] bytes = upa.getData();
        UserPasswordAttribute upa2 = new UserPasswordAttribute(bytes);
        String pwd = upa2.extractPassword(ra, secret);
        Assert.assertEquals(pwd, pwd15, "15 character password should be the same after decoding.");
    }

    /**
     * Tests the first boundary incurrence meaning the password length is one char more than the 16 byte hash used for
     * XOR'ing.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     */
    @Test
    public void test16charPwd() throws NoSuchAlgorithmException, IOException {
        String pwd = "123456789_123456";
        SecureRandom rand = new SecureRandom();
        RequestAuthenticator ra = new RequestAuthenticator(rand, secret);
        UserPasswordAttribute upa = new UserPasswordAttribute(ra, secret, pwd);
        byte[] bytes = upa.getData();
        UserPasswordAttribute upa2 = new UserPasswordAttribute(bytes);
        String pwd2 = upa2.extractPassword(ra, secret);
        Assert.assertEquals(pwd2, pwd, "16 character password should be the same after decoding.");
    }

    @Test
    public void test36charPwd() throws NoSuchAlgorithmException, IOException {
        String pwd = "123456789_123456789_123456";
        SecureRandom rand = new SecureRandom();
        RequestAuthenticator ra = new RequestAuthenticator(rand, secret);
        UserPasswordAttribute upa = new UserPasswordAttribute(ra, secret, pwd);
        byte[] bytes = upa.getData();
        UserPasswordAttribute upa2 = new UserPasswordAttribute(bytes);
        String pwd2 = upa2.extractPassword(ra, secret);
        Assert.assertEquals(pwd2, pwd, "36 character password should be the same after decoding.");
    }

    @Test
    public void testMultiByteCharPwd() throws NoSuchAlgorithmException, IOException {
        String pwd = "\u30BD\u30D5\u30C8\u30A6\u30A7\u30A2\u5EFA\u7BC9\u5BB6"; // "software architect" in japanese
        System.out.println("- " + pwd);
        SecureRandom rand = new SecureRandom();
        RequestAuthenticator ra = new RequestAuthenticator(rand, secret);
        UserPasswordAttribute upa = new UserPasswordAttribute(ra, secret, pwd);
        byte[] bytes = upa.getData();
        UserPasswordAttribute upa2 = new UserPasswordAttribute(bytes);
        String pwd2 = upa2.extractPassword(ra, secret);
        Assert.assertEquals(pwd2, pwd, "multibyte character password should be the same after decoding.");
    }

}
