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