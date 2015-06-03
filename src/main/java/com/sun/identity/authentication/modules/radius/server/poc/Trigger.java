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
package com.sun.identity.authentication.modules.radius.server.poc;

/**
 * Abstract parent of all triggers causing transitions between states. Subclasses must also implement domain specific
 * static builder methods for instantiating configured instances of their specific triggers. For example, a UserSelects
 * subclass could have the following build method:
 *
 * <pre>
 * public static UserSelects value(String selection) {
 *     return new UserSelects(selection);
 * }
 * </pre>
 *
 * This would enable configuring a Trigger via UserSelects("T") which is very readable and comprehensible. Created by
 * markboyd on 6/28/14.
 */
public abstract class Trigger {

    protected Trigger() {
    }

    /**
     * Implementations MUST implement to support their functionality.
     * 
     * @param req
     * @param ctx
     * @return
     */
    public abstract boolean isTriggered(RequestInfo req, Context ctx);
}
