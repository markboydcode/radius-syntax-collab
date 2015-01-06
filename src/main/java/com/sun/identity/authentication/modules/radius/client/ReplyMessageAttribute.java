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
 * $Id: ReplyMessageAttribute.java,v 1.2 2008/06/25 05:42:02 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package com.sun.identity.authentication.modules.radius.client;

import java.io.IOException;

public class ReplyMessageAttribute extends Attribute
{
	private byte _value[] = null;
	private String _str = null;

    /**
     * Creates a ReplyMessageAttribute from the on-the-wire octets.
     *
     * @param value
     */
	public ReplyMessageAttribute(byte value[])
	{
		super();
		_t = REPLY_MESSAGE;
		_str = new String(value, 2, value.length - 2);
		_value = value;
	}

    /**
     * Creates a ReplyMessageAttribute to contain the given String message prior to sending in a packet.
     * If the String is greater than 255 bytes then it is trimmed down to below that length.
     *
     * @param message
     */
    public ReplyMessageAttribute(String message) {
        super();
        _t = REPLY_MESSAGE;
        _str = message;
        byte[] bytes = message.getBytes();

        if (bytes.length > MAX_ATTRIBUTE_VALUE_LENGTH) {
            // there has to be a better way to trim down to really close to max value but for now
            // since characters are generally two bytes in java chop to half max chars then drop
            // five chars at a time until byte count is below max
            String shortened = message.substring(0, (MAX_ATTRIBUTE_VALUE_LENGTH/2 -1));
            bytes = shortened.getBytes(); // this is lossy without charset!!!

            while (bytes.length > MAX_ATTRIBUTE_VALUE_LENGTH) {
                shortened = shortened.substring(0, shortened.length()-5);
                bytes = shortened.getBytes();
            }
            _str = shortened;
        }
        _value = new byte[bytes.length + 2];
        _value[0] = (byte) _t;
        _value[1] = (byte) bytes.length;
        System.arraycopy(bytes, 0, _value, 2, bytes.length);
    }

	public String getString()
	{
		return _str;
	}

	public byte[] getValue() throws IOException
	{
		return _str.getBytes();
	}

    /**
     * Creates how ever many ReplyMessageAttribute objects are needed to convey the given message
     * returning them in an ordered array with the first object containing the initial characters
     * of the message and the last object containing the characters toward the end of the message.
     *
     * @param message
     * @return
     */
    public static ReplyMessageAttribute[] fromMessage(String message) {
        // take what is in constructor and generalize it to handle enough objects to contain the message
        return null;
    }

    public String toStringImpl() {
        return _str;
    }
}
