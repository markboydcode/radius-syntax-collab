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
package com.sun.identity.authentication.modules.radius.server.config;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import com.sun.identity.sm.DefaultValues;

/**
 * Generates a random, alphanumeric 16 character Created by markboyd on 11/7/14.
 */
public class DefaultClientSecretGenerator extends DefaultValues {
    private static final Random numGen = new SecureRandom();

    /**
     * The characters that we choose to place in our default generated client secret.
     */
    private static final String allowedChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    @Override
    public Set getDefaultValues() {
        return generateSecretHolder();
    }

    /**
     * Generates client secret of 16 octets in length with characters selected randomly from allowedChars.
     *
     * @return
     */
    private Set generateSecretHolder() {
        StringBuilder secret = new StringBuilder();
        // rfc2865 says "It is preferred that the secret be 16 octets". However, we use 16 characters since ascii
        // chars have an empty first byte in a java character.
        for (int i = 0; i < 16; i++) {
            int idx = numGen.nextInt(allowedChars.length()); // will gen int from 0 to length exclusive
            secret.append(allowedChars.charAt(idx));
        }
        Set holder = new HashSet();
        holder.add(secret.toString());
        return holder;
    }

}
