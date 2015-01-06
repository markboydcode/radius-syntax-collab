package com.sun.identity.authentication.modules.radius.server.poc;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Implements automated calls with delivery of passcode by generated voice.
 *
 * Created by markboyd on 8/2/14.
 */
public class VoiceService {
    private static final String AcctSid = "ACa48f2316ff66d87e8d915fa2ba1cce78";
    private static final String AcctAuthToken = "149b3b88b54356c6449a1eff13034d34";

    private static final String TwilioApiBase = "https://api.twilio.com/2010-04-01/Accounts/" + AcctSid + "/Calls.json";
    private static final String TwilioOwnedNumber = "+1801-663-7825";
    private static final String TwimletsBase = "http://twimlets.com/echo?Twiml=";
    private static final int PasscodeDigits = 4;
    private static final MessageFormat Message = contructMessageTemplate(PasscodeDigits);
    private static final Random numGen = new Random();

    /**
     * String prepended to the submitted phone number to which voice messages should go for a user. The number so
     * prepended is then stored in UsersPropfile.add().
     */
    public static final String PAIRING_PREFIX = "voice-passcode:";

    /**
     * Character used as a divider between multiple property values in the stateholder where needed to pass multiple
     * values through the state property to the radius client and back.
     */
    public static final String STATEHOLDER_PROPERIES_SEPARATOR = ":";


    private static MessageFormat contructMessageTemplate(int passcodeDigits) {
        StringBuilder sb = new StringBuilder()
                .append("<Response><Say>Your passcode from {0} for {1} to {2} is</Say>");

        for(int i=0; i<passcodeDigits; i++) {
            if (i!= 0) {
                sb.append("<Pause length=''1''/>");
            }
            sb.append("<Say>{")
                    .append(i+3)
                    .append("}</Say>");
        }
        sb.append("</Response>");
        return new MessageFormat(sb.toString());
    }

    /**
     * Trigger that verifies a voice pairing exists and
     * places the number in req.devicePairingId for consumption by the BaseRequestProcessor nested class.
     */
    public static Trigger userHasServicePairedDevice() {
        return new Trigger() {
            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                String pairing = UsersProfile.getPairings().getProperty(req.username);
                if (pairing != null && pairing.startsWith(PAIRING_PREFIX)) {
                    req.devicePairingId = pairing.substring(PAIRING_PREFIX.length());
                    return true;
                }
                return false;
            }
        };
    }


    public static TransitionProcessor requestAuthorizationFor(String s) {
        return new BaseRequestProcessor(s);
    }

    public static TransitionProcessor requestPairingOfDevice() {
        return new BaseRequestProcessor("pair this device and access V P N");
    }

    /**
     * Trigger that returns true if the submitted text DOES conforms to
     * E.164 (starts with a '+' character [and for prototype U.S. country code '1']). Also sets as the req.devicePairingId
     * for consumption by the BaseRequestProcessor nested class.
     *
     * Called when acquiring phone number to be paired with this user. Verifies that the submitted format conforms to
     * E.164 (starts with a '+' character [and for prototype U.S. country code '1']) and
     * places the number in req.devicePairingId for consumption by the BaseRequestProcessor nested class.
     *
     * @return
     */
    public static Trigger enteredNumberHasValidFormat() {
        return new Trigger() {
            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                // E.164 format starts with '+' and country code, 1=US only supported in POC
                if (req.credential.startsWith("+1")) {
                    req.devicePairingId = req.credential; // leave in E.164 format since twilio supports it
                    SmsService.setPhoneNumberInStateHolder(req.stateHolder, req.devicePairingId);
                    return true;
                }
                return false;
            }
        };
    }

    private static class BaseRequestProcessor extends TransitionProcessor {

        /**
         * The action that will be specified in the message.
         */
        private final String action;

        private BaseRequestProcessor(String actionMsg) {
            this.action = actionMsg;
        }

        @Override
        public void process(RequestInfo req, Context ctx, String message) {

            HttpClientBuilder builder = HttpClients.custom()
                    .disableAutomaticRetries()
                    .disableRedirectHandling()
                    .setDefaultSocketConfig(
                            // ensures that if a server error drops the connection or doesn't
                            // respond we don't wait for the default 30 seconds of inactivity
                            // before TCP throwing a socket timeout error.
                            SocketConfig.custom().setSoTimeout(3000).build()
                    );

            CloseableHttpClient client = builder.build();
            HttpPost post = new HttpPost(TwilioApiBase);

            // build www-url-form-encoded payload
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("From", TwilioOwnedNumber));

            // text entered in challenge field must be in form +1801-664-0964
            params.add(new BasicNameValuePair("To", req.devicePairingId));
            params.add(new BasicNameValuePair("Url", getTwimlUrl(req, this.action)));

            try {
                post.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
            } catch(UnsupportedEncodingException ue) {
                System.out.println("Unable to encode form entity.");
                ue.printStackTrace();
            }

            post.addHeader(new BasicHeader("Accept", "application/json"));
            post.addHeader(new BasicHeader("Accept-Charset", "utf-8"));

            String usrColonToken = AcctSid + ":" + AcctAuthToken;
            String authHeaderVal = "Basic " + DatatypeConverter.printBase64Binary(usrColonToken.getBytes(Charset.defaultCharset()));
            System.out.println("---> " + authHeaderVal);

            post.addHeader(new BasicHeader("Authorization", authHeaderVal));

            CloseableHttpResponse resp = null;
            try {
                resp = client.execute(post);
                System.out.println("Response Code: " + resp.getStatusLine().getStatusCode());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static String getTwimlUrl(RequestInfo req, String action) {
        // build twiml for echo twimlet to return to handle the call flow
        String organization = "The L D S Church";

        // inject entered username with spaces between chars to is sounds them out. todo: Replace with profile name in real system.
        StringBuffer user = new StringBuffer();
        for(int i=0; i<req.username.length(); i++) {
            user.append(req.username.charAt(i)).append(" ");
        }
        Object[] parms = new Object[3 + PasscodeDigits];
        parms[0] = organization;
        parms[1] = user.toString().trim();
        parms[2] = action;

        StringBuilder pc = new StringBuilder();

        for(int i=0; i<PasscodeDigits; i++) {
            int digit = numGen.nextInt(10);
            pc.append(digit);
            parms[i+3] = digit; // will gen int from 0 to 9 inclusive
        }

        SmsService.setPasscodeInStateHolder(req.stateHolder, pc.toString());
        String msg = Message.format(parms);
        System.out.println("msg: " + msg);
        msg = utf8UrlEncode(msg);
        String twimlUrl = TwimletsBase + msg;

        System.out.println("twiml url is: " + twimlUrl);
        return twimlUrl;
    }

    /**
     *
     * @param value
     * @return
     */
    private static String utf8UrlEncode(String value) {
        try {
            return URLEncoder.encode(value, "utf-8");
        } catch (UnsupportedEncodingException e) {
            // ignore since should never happen given that utf-8 is fundamental to the jvm
        }
        return value; // if utf-8 isn't in the jvm we have no choice but to send it as-is
    }


    public static Trigger pairingRequestFailed() {
        return SmsService.pairingRequestFailed();
    }

    public static Trigger pairingRequestWasApproved() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                if (SmsService._enteredPasscodeIsValid(req, ctx)) {
                    String phoneNum = SmsService.getPhoneNumberFromStateHolder(req.stateHolder);
                    UsersProfile.addPairing(req.username, PAIRING_PREFIX + phoneNum);
                    return true;
                }
                return false;
            }
        };
    }


    // ----- authN Req approved/failed triggers : identical to those of sms service

    public static Trigger authNRequestWasApproved() {
        return SmsService.authNRequestWasApproved();
    }

    public static Trigger authNRequestWasDenied() {
        return SmsService.authNRequestWasDenied();
    }



}
