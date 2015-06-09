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
 * Contains directly or in contained packages all radius related functionality for openam including:
 *
 * <pre>
 *     Classes representing the radius on-the-wire constructs like packets and attributes and facilitating
 *     translation between the java objects and the on-the-wire protocol.
 *
 *     An authentication module enabling openAM to act as a radius client prompting for username and password and then
 *     authenticating users against a remote radius server.
 *
 *     Radius server support enabling openAM to act as a radius server, define remote clients allowed to connect, and
 *     the authentication realm and chain to authenticate users for that client.
 * </pre>
 *
 * Created by boydmr on 6/4/15.
 */
package com.sun.identity.authentication.modules.radius;