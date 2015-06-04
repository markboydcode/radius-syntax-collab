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

/**
 * Abstract superclass of all authenticator types.
 */
public abstract class Authenticator {

    /**
     * Returns the on-the-wire bytes for writing a given authenticator onto the wire.
     *
     * @return the bytes to be written representing the authenticator instance.
     *
     * @throws java.io.IOException if unable to generate the on-the-wire octets for the authenticator
     */
    public abstract byte[] getData() throws IOException;
}
