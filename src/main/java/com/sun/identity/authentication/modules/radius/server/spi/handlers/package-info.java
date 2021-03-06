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

/**
 * Implementations of handlers and related context object for receiving and processing radius server traffic including:
 *
 * <pre>
 *     An accept-all handler that always returns an Access-Accept packet for testing purposes only.
 *
 *     A reject-all handler that always returns an Access-Reject packet for testing purposes only.
 *
 *     A handler that expects client configuration from the admin console to indicate the realm and chain to be used
 *     for authenticating users including translating callback handlers into Access-Challenge responses and
 *     subsequent Access-Requests that take user entered answers and inject them into the callbacks prior to
 *     submitting to openAM's authentication context and repeating until all callbacks have been consumed and
 *     authentication fails or succeeds.
 *
 * </pre>
 *
 * Created by boydmr on 6/4/15.
 */
package com.sun.identity.authentication.modules.radius.server.spi.handlers;