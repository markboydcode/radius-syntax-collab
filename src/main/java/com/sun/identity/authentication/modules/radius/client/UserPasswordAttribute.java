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
 * Portions Copyrighted [2011] [ForgeRock AS]
 * Portions Copyrighted [2015] [Intellectual Reserve, Inc (IRI)]
 */
package com.sun.identity.authentication.modules.radius.client;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Class representing the  User Password Attribute as defined in section 5.2 of RFC 2865.
 */
public class UserPasswordAttribute extends Attribute {

    /**
     * The pseudo-random Request Authenticator used for encrypting the password.
     */
    private Authenticator ra = null;
    /**
     * The shared secret between the client and server used for encrypting the password.
     */
    private String secret = null;

    /**
     * The clear text representation of the password.
     */
    private String password = null;

    /**
     * Indicate in which direction we are processing since the algorithm is mostly the same save for building the md5
     * hash blocks after the initial one. For encrypting it pulls from the resultant cipher text. For decrypting, the
     * cipher text is what is being decrypted (via XOR'ing again with the same hashes) so the hashes must be generated
     * using the cipher texts so that they are the same else XOR'ing's restorative nature won't work resulting in all
     * characters past the first 16 character block being garbled.
     */
    private static enum Direction {
        ENCRYPT,
        DECRYPT;
    }

    /**
     * The raw on-the-wire bytes representing this attribute when instantiated to recover password.
     */
    private byte [] raw = null;

    /**
     * Instantiates attribute for decrypting cipher-text to restore password.
     *
     * @param data the on-the-wire representation of the cipher text
     */
    public UserPasswordAttribute(byte[] data) {
        super(USER_PASSWORD);
        raw = data;
    }

    /**
     *Instantiates attribute for creation of cipher text from plain text password.
     *
     * @param ra the Request Authenticator used for the encrypting the first 16 characters of the password.
     * @param secret the shared secret between the client and the server used for the creation of the cipher text.
     * @param password The plain text password.
     */
    public UserPasswordAttribute(Authenticator ra, String secret, String password) {

        super(USER_PASSWORD);
        this.ra = ra;
        this.secret = secret;
        this.password = password;
    }

    /**
     * Private class for the converting of plain text password to cipher text, or cipher text to plain text.
     * @param value the on the wire representation of the plain text password or cipher text
     * @param direction which direction operation will take place either ENCRYPT or DECRYPT
     * @return on the wire representation of either encrypted or decrypted password
     * @throws IOException upon invalid Request Authenticator object
     */

    private byte[] convert(byte[] value, Direction direction) throws IOException {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage());
        }
        md5.update(secret.getBytes());
        md5.update(ra.getData());
        byte [] sum = md5.digest();

        byte [] up = value;
        int oglen = (up.length / 16);

        // increase number of blocks in output array if we don't have a multiple of 16 bytes in value
        if (up.length % 16 != 0) {
            oglen = oglen + 1;
        }
        byte [] ret = new byte[oglen * 16];
        for (int i = 0; i < ret.length; i++) {
            if ((i % 16) == 0) {
                md5.reset();
                md5.update(secret.getBytes());
            }
            if (i < up.length) {
                ret[i] = (byte) (sum[i % 16] ^ up[i]);
            } else {
                ret[i] = (byte) (sum[i % 16] ^ 0);
            }

            // always use the cipher bytes for updating the md5 hashes otherwise all blocks after the first will be
            // garbled upon decrypting rendering all passwords greater than 16 characters useless since they will be
            // incorrect.
            if (direction == Direction.ENCRYPT) {
                md5.update(ret[i]);

            } else {
                md5.update(up[i]);
            }
            if ((i % 16) == 15) {
                sum = md5.digest();
            }
        }
        return ret;
    }

    /**
     * Creates the value portion of the on-the-wire representation of this attribute.
     *
     * @return the on the wire representation of the cipher-text password
     * @throws IOException if password is not correctly instantiated
     */
    public byte[] getValue() throws IOException {

        return convert(password.getBytes(), Direction.ENCRYPT);
    }

    /**
     * Creates on-the-wire representation of this attribute.
     *
     * @return the on-the-wire representation of this attribute, and header.
     * @throws IOException when invalid data is returned by getValue method.
     */
    public byte[] getData() throws IOException {
        byte[] value = this.getValue();
        byte[] ret = new byte[value.length + 2];
        ret[0] = USER_PASSWORD;
        ret[1] = (byte) ret.length;
        System.arraycopy(value, 0, ret, 2, value.length);
        return ret;
    }

    /**
     * Extracts the plain text password from the cipher text.
     * @param a pseudo-random Request Authenticator
     * @param secret the shared secret between the client and server used for cipher text generation.
     * @return Clear text password
     * @throws IOException if unable to correctly determine secret, authenticator, or if invalid values are given for
     * cipher text.
     */

    public String extractPassword(Authenticator a, String secret) throws IOException {
        this.ra = a;
        this.secret = secret;
        // trims off sign extension bits, subtracts type and length prefix octets
        int valLen = (((int) raw[1]) & 0xFF) - 2;
        byte[] cypherText = new byte[valLen];
        System.arraycopy(raw, 2, cypherText, 0, valLen);
        byte[] clearText = convert(cypherText, Direction.DECRYPT);

        // trim off any null padding
        int i = 0;
        for (; i < clearText.length; i++) {
            if (clearText[i] == 0) {
                break;
            }
        }
        password = new String(clearText, 0, i);
        return password;
    }

    /**
     * Version of toStringImpl() to be used in concert with commented code in RadiusRequestHandler for logging
     * incoming passwords on the server when there were problems with the decryption algorithm.
     *
     * @return plain-text representation of password
     */
//    public String toStringImpl() {
//        return password; // don't dump password to logs
//    }

    public String toStringImpl() {
        return "*******"; // don't dump password to logs
    }
}
