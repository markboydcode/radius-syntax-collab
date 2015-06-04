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