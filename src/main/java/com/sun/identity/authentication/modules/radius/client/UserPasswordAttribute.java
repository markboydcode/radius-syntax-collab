/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: UserPasswordAttribute.java,v 1.2 2008/06/25 05:42:02 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package com.sun.identity.authentication.modules.radius.client;

import java.security.*;
import java.io.*;

public class UserPasswordAttribute extends Attribute
{
	private Authenticator _ra = null;
	private String _secret = null;
	private String _password = null;

    /**
     * The raw on-the-wire bytes representing this attribute when instantiated to recover password.
     */
    private byte[] _raw = null;

    /**
     * Instantiates attribute for decrypting cyphertext to restore password.
     *
     * @param data
     */
	public UserPasswordAttribute(byte[] data) {
        super(USER_PASSWORD);
        _raw = data;
    }

    /**
     * Creates attribute with clear text password to be encrypted.
     *
     * @param ra
     * @param secret
     * @param password
     */
	public UserPasswordAttribute(Authenticator ra, String secret, String password)
	{
		super(USER_PASSWORD);
		_ra = ra;
		_secret = secret;
		_password = password;
	}

    private byte[] convert(byte[] value) throws IOException {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage());
        }
        md5.update(_secret.getBytes());
        md5.update(_ra.getData());
        byte sum[] = md5.digest();

        byte up[] = value;
        int oglen = (up.length/16) + 1;
        byte ret[] = new byte[oglen * 16];
        for (int i = 0; i < ret.length; i++) {
            if ((i % 16) == 0) {
                md5.reset();
                md5.update(_secret.getBytes());
            }
            if (i < up.length) {
                ret[i] = (byte)(sum[i%16] ^ up[i]);
            } else {
                ret[i] = (byte)(sum[i%16] ^ 0);
            }
            md5.update(ret[i]);
            if ((i % 16) == 15) {
                sum = md5.digest();
            }
        }
        return ret;
    }

    /**
     * Creates the value portion of the on-the-wire representation of this attribute.
     *
     * @return
     * @throws IOException
     */
	public byte[] getValue() throws IOException
	{
        return convert(_password.getBytes());
	}

    /**
     * Creates on-the-wire representation of this attribute.
     *
     * @return
     * @throws IOException
     */
    public byte[] getData() throws IOException {
        byte[] value = this.getValue();
        byte[] ret = new byte[value.length + 2];
        ret[0] = USER_PASSWORD;
        ret[1] = (byte) ret.length;
        System.arraycopy(value, 0, ret, 2, value.length);
        return ret;
    }

    public String extractPassword(Authenticator a, String secret) throws IOException {
        _ra = a;
        _secret = secret;

        int valLen = (((int) _raw[1]) & 0xFF) -2; // trims off sign extension bits, subtracts type and length prefix octets
        byte[] cypherText = new byte[valLen];
        System.arraycopy(_raw, 2, cypherText, 0, valLen);
        byte[] clearText = convert(cypherText);

        // trim off any null padding
        int i = 0;
        for(; i<clearText.length; i++) {
            if (clearText[i] == 0) {
                break;
            }
        }
        return new String(clearText, 0, i);
    }

    public String toStringImpl() {
        return "*******"; // don't dump password to logs
    }
}
