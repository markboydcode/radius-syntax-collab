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
package com.sun.identity.authentication.modules.radius;

/**
 * Defines States of the authentication process. Uniqueness and some descriptive indication is what is important here.
 * The real definition of where these fit is defined in the transitions. We only need unique items here and then use
 * them in configuring our transitions. Created by markboyd on 7/24/14.
 */
public enum State {

    /**
     * The state when users submit their username and password to authenticate.
     */
    STARTING,

    CHOOSE_WHICH_MULTIFACTOR,

    CHOOSE_WHICH_RESPONDER,

    AWAIT_UNSUPPORTED_FEATURE,

    TOOPHER_GET_PAIRING_PHRASE,

    TOOPHER_AWAIT_PAIRING_APPROVAL,

    TOOPHER_AWAIT_DEVICE_APPROVAL,

    GET_SMS_PHONE_NUMBER, // solicit phone number for recieving SMS calls

    VERIFY_SMS_PHONE_NUMBER, // prompts user that an sms text was sent to their indicated numbrer and must be entered to
                             // verify (pair it with that user) and be authorized

    AWAIT_SMS_DELIVERED_PASSCODE, // prompts user that an sms text was sent to their previously registered numbrer and
                                  // must
    // be entered for authorization

    GET_VOICE_PHONE_NUMBER,

    VERIFY_VOICE_PHONE_NUMBER, // propts user that voice delivered passcode has been sent and must be entered to verify
                               // phone number

    AWAIT_VOICE_DELIVERED_PASSCODE, // prompts user that an voice delivered passcode was sent to their previously
                                    // registered numbrer and must
    // be entered for authorization

    DONE,

    /**
     * The state that indicates that the user does not have a mobile number registered in lds account
     */
    MISSING_MOBILE_NUMBER,
    /**
     * The state indicating that the user's mobile number has not yet been verified in lds account.
     */
    MISSING_VERIFIED_MOBILE_NUMER;
}
