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
 * $Id: Packet.java,v 1.2 2008/06/25 05:42:02 qcheng Exp $
 *
 */

/*
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.PacketType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public abstract class Packet
{

	protected PacketType type = null;
	protected short _id = 0;
	protected Authenticator _auth = null;
	protected AttributeSet _attrs = new AttributeSet();

    public Packet(PacketType packetType)
	{
        type = packetType;
	}

	public Packet(PacketType packetType, short id, Authenticator auth)
	{
        this(packetType);
		_id = id;
		_auth = auth;
	}

	public PacketType getType() { return type; }

	public short getIdentifier()
	{
		return _id;
	}

    public void setIdentifier(short id) { this._id = id; }

	public Authenticator getAuthenticator()
	{
		return _auth;
	}

	public void addAttribute(Attribute attr)
	{
		if (attr != null) {
            _attrs.addAttribute(attr);
        }
	}

	public AttributeSet getAttributeSet()
	{
		return _attrs;
	}

	public Attribute getAttributeAt(int pos)
	{
		return _attrs.getAttributeAt(pos);
	}

	public String toString()
	{
		return "Packet [code=" + type.getTypeCode() + ",id=" + (_id & 0xFF) + "]";
	}

    public void setAuthenticator(Authenticator authenticator) {
        this._auth = authenticator;
    }

    /**
     * Get the on-the-wire octet sequence for this packet conforming to rfc 2865.
     *
     * @return
     */
    public byte[] getData() {
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        byte[] bytes = null;
        s.write(type.getTypeCode());
        s.write(_id);
        try {
            s.write(new byte[]{0, 0}); // two octets of length
        } catch (IOException e) {
            // won't happen with ByteArrayOutputStream
        }
        try {
            bytes = _auth.getData();
        } catch (IOException e) {
            e.printStackTrace(); // TODO
        }

        try {
            s.write(bytes);
        } catch (IOException e) {
            // won't happen with ByteArrayOutputStream
        }

        for(int i=0; i<_attrs.size(); i++) {
            Attribute a = _attrs.getAttributeAt(i);

            try {
                bytes = a.getData();
            } catch (IOException e) {
                e.printStackTrace(); // TODO
            }
            try {
                s.write(bytes);
            } catch (IOException e) {
                // won't happen with ByteArrayOutputStream
            }
        }
        byte[] res = s.toByteArray();
        // now poke length in - big endian - network byte order
        res[2] = ((byte)((res.length >> 8) & 0xFF));
        res[3] = ((byte)(res.length & 0xFF));
        return res;
    }
}
