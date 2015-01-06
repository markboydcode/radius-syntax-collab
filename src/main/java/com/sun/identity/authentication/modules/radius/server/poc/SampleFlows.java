package com.sun.identity.authentication.modules.radius.server.poc;

import com.sun.identity.authentication.modules.radius.State;

/**
 * Created by markboyd on 10/20/14.
 */
public enum SampleFlows {

    POC_ORIGINAL_WITH_PROVISIONING_MENU("3wayPoc", SampleFlows.create3wayPocFlow()),
    // ----------------------------------------------------------------------------------------------------------------
    /*
    This flow provides features for demonstrating what we expect the real user experience to be where they may not
    have a mobile number in their profile or their number has not been validated/verfied. If the password is "nop"
    which is short for no phone then the response is the former message. If the password is "nov" which is short for
    not verified then they get the not-verified message. If the password is prefixed with "+1" and is 10 digits long it
    will be used as their phone number and persisted for later attempts. If the password is empty or any other value
    it is treated as "nop". The "nop" and "nov" values demo the corresponding messages but don't remove a previous
    provisioning. If an empty password is used the next time the sms text will be sent.
     */
    SMS_PROD_DEMO_NO_PROVISIONING("smsProdDemo", new Flow()
            .addDefaultState(State.STARTING)

            .add(State.STARTING, "",
                    // if password starts with '+' and has the length of a phone number we will attempt to set up
                    // a new pairing.
                    Transition.to(State.VERIFY_SMS_PHONE_NUMBER)
                            .when(UserEnters.phrase())
                            .and(SmsService.enteredNumberHasValidFormat()) // +1##########
                            .then(SmsService.sendTextMessage("", "{3} is your LDS Account Verification Code for {1}."))
                            .then(Send.radiusChallenge()),
                    // Your passcode from {0} for {1} to {2} is {3}
                    // where 0 = org, 1 = username, 2 = action, 3 = passcode
                    // if password is empty or "bad" reject and send to Done state.
                    Transition.to(State.DONE)
                            .when(new Trigger() {
                                @Override
                                public boolean isTriggered(RequestInfo req, Context ctx) {
                                    return req.credential == null || req.credential.equals("bad");
                                }
                            })
                            .then(Send.radiusAccessReject("bad password")),

                    // is password is 'nop' we return a message indicating that they are missing a mobile number so a
                    // user with pairing can still demo the no mobile message but leave pairing intact.
                    Transition.to(State.MISSING_MOBILE_NUMBER)
                            .when(new Trigger() {
                                @Override
                                public boolean isTriggered(RequestInfo req, Context ctx) {
                                    return "nop".equals(req.credential);
                                }
                            })
                            .then(Send.radiusChallenge()),

                    // is password is 'nov' we return a message indicating that they are missing a validated mobile number
                    // ditto for above message about pairing relationship
                    Transition.to(State.MISSING_VERIFIED_MOBILE_NUMER)
                            .when(new Trigger() {
                                @Override
                                public boolean isTriggered(RequestInfo req, Context ctx) {
                                    return "nov".equals(req.credential);
                                }
                            })
                            .then(Send.radiusChallenge()),

                    // else if they enter nothing we check for previous pairing
                    Transition.to(State.AWAIT_SMS_DELIVERED_PASSCODE)
                            .when(SmsService.userHasServicePairedDevice())
                            .then(SmsService.sendTextMessage("", "{3} is your LDS Account Verification Code for {1}."))
                            .then(Send.radiusChallenge()),

                    // else any othe password or empty password we treat as missing mobile number
                    Transition.to(State.MISSING_MOBILE_NUMBER)
                            .when(UserEnters.nothing())
                            .then(Send.radiusChallenge()),

                    Transition.to(State.MISSING_MOBILE_NUMBER)
                            .when(UserEnters.aPassword())
                            .then(Send.radiusChallenge())
                    )


            .add(State.VERIFY_SMS_PHONE_NUMBER, "" +
                            "Please enter the verification code sent to your mobile phone, then press Continue.\n",

                    Transition.to(State.DONE)
                            .when(UserEnters.nothing())
                            .then(Send.radiusAccessReject("nothing submitted")),

                    Transition.to(State.DONE)
                            .when(SmsService.pairingRequestWasApproved())
                            .then(Send.radiusAccessAllowed()),

                    Transition.to(State.DONE)
                            .when(SmsService.pairingRequestFailed())
                            .then(Send.radiusAccessReject("submitted passcode does not match"))
            )

            .add(State.MISSING_VERIFIED_MOBILE_NUMER, "" +
//            "You have not yet selected a secondary means of Authenticating. " +
//            "You can change your preferred mechanism at any time in your LDS Profile.\n\n" +
                            "Please enter the verification code sent to your mobile phone. If you do " +
                            "not receive a code, verify your mobile number at " +
                            "ldsaccount.lds.org\n",

                    Transition.to(State.DONE)
                            .when(UserEnters.phrase())
                            .then(Send.radiusAccessReject("User Must First Verify their Mobile Number"))
                    )

            .add(State.MISSING_MOBILE_NUMBER, "" +
//            "You have not yet selected a secondary means of Authenticating. " +
//            "You can change your preferred mechanism at any time in your LDS Profile.\n\n" +
                            "Please enter the verification code sent to your mobile phone. If you do " +
                            "not receive a code, confirm your mobile number at " +
                            "ldsaccount.lds.org\n",

                    Transition.to(State.DONE)
                            .when(UserEnters.phrase())
                            .then(Send.radiusAccessReject("User Must First Provide a Mobile Number"))
                    )

            .add(State.AWAIT_SMS_DELIVERED_PASSCODE, "" +
                            "Please enter the verification code sent to your mobile phone, then press Continue.\n",

                    Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                            .when(UserEnters.nothing())
                            .then(Send.radiusChallenge()),

                    Transition.to(State.DONE)
                            .when(SmsService.authNRequestWasApproved())
                            .then(Send.radiusAccessAllowed()),

                    Transition.to(State.DONE)
                            .when(SmsService.authNRequestWasDenied())
                            .then(Send.radiusAccessReject("submitted passcode does not match"))
            )

            .add(State.DONE, "")
    ),
            // ----------------------------------------------------------------------------------------------------------------
    /*
    This flow allows quickly spin up of a test RADIUS server that returns an AccessAllowed for all requests.
     */
    ALLOW_ALL_REQUESTS("allowAllRequests", new Flow()
                            .addDefaultState(State.STARTING)

                            .add(State.STARTING, "",
                                    // if password starts with '+' and has the length of a phone number we will attempt to set up
                                    // a new pairing.
                                    Transition.to(State.DONE)
                                            .when(new Trigger() {
                                                @Override
                                                public boolean isTriggered(RequestInfo req, Context ctx) {
                                                    return true;
                                                }
                                            })
                                            .then(Send.radiusAccessAllowed())
                            )
            ),
    // ----------------------------------------------------------------------------------------------------------------
    /*
    This flow allows quickly spin up of a test RADIUS server that returns an AccessReject for all requests.
     */
    DENY_ALL_REQUESTS("denyAllRequests", new Flow()
            .addDefaultState(State.STARTING)

            .add(State.STARTING, "",
                    // if password starts with '+' and has the length of a phone number we will attempt to set up
                    // a new pairing.
                    Transition.to(State.DONE)
                            .when(new Trigger() {
                                @Override
                                public boolean isTriggered(RequestInfo req, Context ctx) {
                                    return true;
                                }
                            })
                            .then(Send.radiusAccessReject("rejecting everyone today."))
            )
    );

    private static Flow create3wayPocFlow() {

        try{
            return new Flow()
                    .addDefaultState(State.STARTING)

                    .add(State.STARTING, "",
                            // NOTE: we are not validating pwd in this POC but would have to do so
                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    // need to implement this by looking to see if they have previously specified or not.
                                    // for now we let an empty password force re-selection or initial selection so that we
                                    // can demo the full process.
                                    //.when(UsersProfile.hasNoPreferredCallback())
                                    .when(UserEnters.noPassword())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.TOOPHER_AWAIT_DEVICE_APPROVAL)
                                    .when(ToopherService.userHasServicePairedDevice())
                                    .then(ToopherService.requestAuthorizationFor("Access VPN"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.AWAIT_SMS_DELIVERED_PASSCODE)
                                    .when(SmsService.userHasServicePairedDevice())
                                    .then(SmsService.requestAuthorizationFor("Access VPN"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.AWAIT_VOICE_DELIVERED_PASSCODE)
                                    .when(VoiceService.userHasServicePairedDevice())
                                    .then(VoiceService.requestAuthorizationFor("Access V P N"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    //.when(UsersProfile.hasNoPreferredCallback())
                                    .when(UsersProfile.hasNoDevicePairing())
                                    .then(Send.radiusChallenge())
                    )

                    .add(State.CHOOSE_WHICH_MULTIFACTOR, "" +
//            "You have not yet selected a secondary means of Authenticating. " +
//            "You can change your preferred mechanism at any time in your LDS Profile.\n\n" +
                                    "Select your preferred callback mechanism.\n" +
                                    " S for SMART Phone Responder\n" +
                                    " T for TEXT Message Delivered passcode\n" +
                                    " P for PHONE Call Delivered Passcode\n" +
                                    " D for DEVICE Generated Passcode\n" +
                                    "Press Cancel to start over.",

                            Transition.to(State.CHOOSE_WHICH_RESPONDER)
                                    .when(UserSelects.value("S"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.GET_SMS_PHONE_NUMBER)
                                    .when(UserSelects.value("T"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.GET_VOICE_PHONE_NUMBER)
                                    .when(UserSelects.value("P"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.AWAIT_UNSUPPORTED_FEATURE)
                                    .when(UserSelects.value("D"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserSelects.anything())
                                    .then(Send.radiusChallenge())
                    )

                    .add(State.GET_SMS_PHONE_NUMBER, "" +
                                    "Please enter your SMS capable seven digit phone number prefixed with '+' and country code (1 = U.S.) and NO dashes and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.GET_SMS_PHONE_NUMBER)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.VERIFY_SMS_PHONE_NUMBER)
                                    .when(UserEnters.phrase())
                                    .and(SmsService.enteredNumberHasValidFormat())
                                    .then(SmsService.requestPairingOfDevice())
                                    .then(Send.radiusChallenge())
                    )

                    .add(State.GET_VOICE_PHONE_NUMBER, "" +
                                    "Please enter your seven digit phone number prefixed with '+' and country code (1 = U.S.) and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.GET_VOICE_PHONE_NUMBER)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.VERIFY_VOICE_PHONE_NUMBER)
                                    .when(UserEnters.phrase())
                                    .and(VoiceService.enteredNumberHasValidFormat())
                                    .then(VoiceService.requestPairingOfDevice())
                                    .then(Send.radiusChallenge())
                    )

                    .add(State.VERIFY_SMS_PHONE_NUMBER, "" +
                                    "Please enter the passcode that was sent to your device via an SMS text message and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.DONE)
                                    .when(SmsService.pairingRequestWasApproved())
                                    .then(Send.radiusAccessAllowed()),

                            Transition.to(State.DONE)
                                    .when(SmsService.pairingRequestFailed())
                                    .then(Send.radiusAccessReject("submitted passcode does not match"))
                    )

                    .add(State.VERIFY_VOICE_PHONE_NUMBER, "" +
                                    "Please enter the passcode that was conveyed to you by a voice message to your phone and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.DONE)
                                    .when(VoiceService.pairingRequestWasApproved())
                                    .then(Send.radiusAccessAllowed()),

                            Transition.to(State.DONE)
                                    .when(VoiceService.pairingRequestFailed())
                                    .then(Send.radiusAccessReject("submitted passcode does not match"))
                    )

                    .add(State.AWAIT_SMS_DELIVERED_PASSCODE, "" +
                                    "Please enter the passcode that was conveyed to you by an SMS message to your phone and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.DONE)
                                    .when(SmsService.authNRequestWasApproved())
                                    .then(Send.radiusAccessAllowed()),

                            Transition.to(State.DONE)
                                    .when(SmsService.authNRequestWasDenied())
                                    .then(Send.radiusAccessReject("submitted passcode does not match"))
                    )

                    .add(State.AWAIT_VOICE_DELIVERED_PASSCODE, "" +
                                    "Please enter the passcode that was conveyed to you by a voice message to your phone and press Continue.\n",

                            Transition.to(State.CHOOSE_WHICH_MULTIFACTOR)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.DONE)
                                    .when(VoiceService.authNRequestWasApproved())
                                    .then(Send.radiusAccessAllowed()),

                            Transition.to(State.DONE)
                                    .when(VoiceService.authNRequestWasDenied())
                                    .then(Send.radiusAccessReject("submitted passcode does not match"))
                    )

                    .add(State.CHOOSE_WHICH_RESPONDER, "" +
//            "Smart Phone Responders are installed from your device's App Store and allow us to contact that Application when Authenticating and enable you to respond. " +
//            "We currently support the following Smart Phone Responders.\n\n" +
                                    "After you have Installed your preferred Application, Indicate which one you are using.\n" +
                                    " T for Toopher\n" +
                                    " L for LDS Authenticator\n\n" +
                                    "Press Cancel to return to start over.\n",

                            Transition.to(State.TOOPHER_GET_PAIRING_PHRASE)
                                    .when(UserSelects.value("T"))
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.AWAIT_UNSUPPORTED_FEATURE)
                                    .when(UserSelects.anything())
                                    .then(Send.radiusChallenge())
                    )
                    .add(State.AWAIT_UNSUPPORTED_FEATURE, "" +
                                    "That feature is not yet implemented.\n" +
                                    "Press Cancel or Continue to start over.\n",
                            Transition.to(State.DONE)
                                    .when(UserSelects.anything())
                                    .then(Send.radiusAccessReject("Un-implemented feature selected for authentication."))
                    )
                    .add(State.TOOPHER_GET_PAIRING_PHRASE, "" +
                                    "You do not yet have a toopher-paired device. " +
                                    "Open your Toopher Application, request a 'Pairing Phrase', enter it here, and press Continue.\n",
//            "When your pairing phrase is available enter it here and press Continue.\n\n" +
//            "Press Cancel to start over.",

                            Transition.to(State.TOOPHER_GET_PAIRING_PHRASE)
                                    .when(UserEnters.nothing())
                                    .then(Send.radiusChallenge()),

                            Transition.to(State.TOOPHER_AWAIT_PAIRING_APPROVAL)
                                    .when(UserEnters.phrase())
                                    .then(ToopherService.requestPairingOfDevice())
                                    .then(Send.radiusChallenge())
                    )
                    .add(State.TOOPHER_AWAIT_PAIRING_APPROVAL, "" +
                                    "Authorize pairing on your device and then press continue.\n",

                            Transition.to(State.DONE)
                                    .when(ToopherService.pairingRequestWasDenied())
                                    .then(Send.radiusAccessReject("Pairing request denied on device.")),

                            Transition.to(State.TOOPHER_AWAIT_DEVICE_APPROVAL)
                                    .when(ToopherService.pairingRequestWasApproved())
                                    .then(ToopherService.requestAuthorizationFor("VPN Access"))
                                    .then(Send.radiusChallenge())
                    )
                    .add(State.TOOPHER_AWAIT_DEVICE_APPROVAL, "" +
                                    "An access request has been sent to your device. \n\n" +
                                    "Authorize Access on your device and then press continue.\n\n" +
                                    "Press Cancel to start over.\n",

                            Transition.to(State.DONE)
                                    .when(ToopherService.authNRequestWasApproved())
                                    .then(Send.radiusAccessAllowed()),

                            Transition.to(State.DONE)
                                    .when(ToopherService.authNRequestWasDenied())
                                    .then(Send.radiusAccessReject("Device approval was not given."))
                    )
                    .add(State.DONE, "");

        } catch(Throwable t) {
            return null;
        }
    }

    /**
     * The set of states and transitions for a radius client.
     */
    private final Flow flow;

    /**
     * Obtain the configured flow object.
     *
     * @return
     */
    public Flow getFlow() {
        return this.flow;
    }

    /**
     * A short name for this flow.
     */
    private final String moniker;

    SampleFlows(String moniker, Flow flow) {
        this.flow = flow;
        this.moniker = moniker;
    }
}
