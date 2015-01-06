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
 * $Id: GenericAttribute.java,v 1.2 2008/06/25 05:42:01 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.AttributeType;
import com.sun.identity.authentication.modules.radius.Utils;

import java.io.*;

public class GenericAttribute extends Attribute
{
	private byte _value[] = null;

	public GenericAttribute(byte value[])
	{
		super();
		_t = value[0];
		_value = new byte[value.length - 2];
		System.arraycopy(value, 2, _value, 0, _value.length);
	}

	public byte[] getValue() throws IOException
	{
		return _value;
	}

    public String toString() {
        AttributeType t = AttributeType.getType(this.getType());
        StringBuilder s = new StringBuilder();

        if (t == null) {
            try {
                s.append("UNKNOWN TYPE : ")

                        .append(_t)
                        .append(" ")
                        .append(Utils.toHexAndPrintableChars(this.getData())).toString();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else {
            s.append(t);
        }
        String content = this.toStringImpl();

        if (! "".equals(content)) {
            s.append(" : ").append(content);
        }
        return s.toString();
    }

}
