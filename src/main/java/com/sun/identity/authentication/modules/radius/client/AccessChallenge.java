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

import com.sun.identity.authentication.modules.radius.PacketType;

/**
 * Represents in java object for the Access-Challenge packet specified in section 4.4 of RFC 2865.
 */
public class AccessChallenge extends Packet {

    /**
     * Constructs a new Instance.
     */
    public AccessChallenge() {
        super(PacketType.ACCESS_CHALLENGE);
    }
}
