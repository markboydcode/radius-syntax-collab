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
package com.sun.identity.authentication.modules.radius.server.spi.handlers;

import javax.security.auth.callback.Callback;

import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.spi.PagePropertiesCallback;

/**
 * Holds server side info for an authentication conversation in progress for a user via a radius client. Created by
 * markboyd on 11/28/14.
 */
public class ContextHolder {

    /**
     * The page properties callback class that encapsulates properties related to the callback set including some
     * attributes of the Callbacks element such as timeout, header, template, image, and error.
     */
    public PagePropertiesCallback callbackSetProps;

    /**
     * Indicates what phase of authentication we are in. The flow is the same as the order of declaration.
     */
    public static enum AuthPhase {
        STARTING, GATHERING_INPUT, FINALIZING, TERMINATED
    }

    /**
     * The name of the module instance.
     */
    public String moduleName = null;

    /**
     * The zero based index of the current module in the chain for whom we are gather values from the user. Initialized
     * to -1 so that we can centralize updating this info set without regard to whether we are handling the first set or
     * following sets.
     */
    public int chainModuleIndex = -1;

    /**
     * The current set of callbacks being fulfilled by a user through radius.
     */
    public Callback[] callbacks = null;

    /**
     * The zero based index of the current callback (field) whose requirement is being sought through a RADIUS
     * accessChallenge response excluding the undeclared PagePropertiesCallback object that is always first in the array
     * of callbacks and contains the header for the html page in which the fields for this set of callbacks are
     * presented for html clients.
     */
    public int idxOfCurrentCallback = 0;

    /**
     * The zero based index of the set of callbacks within a given module. Modules can have more than one set of
     * callback with a single set translating to a single web page when openam is used for web authentication.
     */
    public int idxOfCallbackSetInModule = 0;

    /**
     * The context object being held in cache.
     */
    public AuthContext authContext;

    /**
     * The millis value of the timeout value for the current callback set. We persist this here so that we still have
     * access to it while processing each callback requiring input from the user. Then for each callback input value
     * received we reset the count since we then know that the user is still with us. So ultimately, when using RADIUS
     * the total time that a user may have entering input values for all callbacks in a set is the number of callbacks
     * times the timeout value for that set. At creation time we instantiate to one minute so that the holder won't get
     * purged from cache between getting created and loading of the first callback set.
     */
    public Long millisExpiryForCurrentCallbacks = 60000L;

    /**
     * The time in the future when this context should be purged from cache ostensibly because the authentication
     * attempt was aborted by that user or they took too long to complete a given step. When System.currentTimeMillis is
     * greater than this value the expiration point has passed and the item should be purged. This value may change
     * multiple times during a given authentication process depending on how many pages of callbacks are incurred. Each
     * set of callbacks has its own declared number of seconds allows for response and that value will be set here when
     * that callback set is incurred.
     */
    public Long millisExpiryPoint = System.currentTimeMillis() + millisExpiryForCurrentCallbacks;

    /**
     * The key for this object in the server-side cache.
     */
    public final String cacheKey;

    /**
     * Indicates in which phase of authentication we are at any point in time.
     */
    public AuthPhase authPhase = AuthPhase.STARTING;

    /**
     * Construct on with its unique key.
     *
     * @param key
     */
    public ContextHolder(String key) {
        this.cacheKey = key;
    }
}
