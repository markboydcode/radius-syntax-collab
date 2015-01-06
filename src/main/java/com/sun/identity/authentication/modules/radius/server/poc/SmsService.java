package com.sun.identity.authentication.modules.radius.server.poc;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.SocketConfig;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.util.Random;

/**
 * Created by markboyd on 7/29/14.
 */
public class SmsService {
    private static final int PasscodeDigits = 4;
    private static final Random numGen = new Random();
    private static final MessageFormat Message = new MessageFormat("Your passcode from {0} for {1} to {2} is {3}");

    public static final String SMS_BASE_URL = "https://ws-stage.ldschurch.org/ws/sms/v2.0/Services/rest/SmsService";
    public static final String SMS_SEND = SMS_BASE_URL + "/sendMessages";

    public static final String APP_USR = "multiFactorAuthentication";
    public static final String APP_PWD = "willYouVerifyWhoYouAreAgainPlease";
    public static final String APP_CODE_KEY = APP_USR;

    /**
     * String prepended to the submitted phone number to which sms message should go for a user. The number so
     * prepended is then stored in UsersPropfile.add
     */
    public static final String PAIRING_PREFIX = "sms-passcode:";

    /**
     * Character used as a divider between multiple property values in the stateholder where needed to pass multiple
     * values through the state property to the radius client and back.
     */
    public static final String STATEHOLDER_PROPERIES_SEPARATOR = ":";


    /**
     * Returns processor that sends sms message with passcode to both pair the device and grant access to VPN in one response.
     * @return
     */
    public static TransitionProcessor requestPairingOfDevice() {
        /*
        this is called after enteredNumberHasValidFormat. That method sets the phone number in the stateholder. The
        BaseRequestProcessor to which this trigger delegates then adds a passcode as well. So for this path there will
        be both a passcode and a phone number.
         */
        return new BaseRequestProcessor("pair this device and access VPN");
    }

    /**
     * For sms service authorization is requested by sending an sms message that includes a passcode to be entered into
     * the challenge field of the radius client. This processor is only requesting autorization meaning the user
     * previously paired a phone number with their profile.
     *
     * @param action
     * @return
     */
    public static TransitionProcessor requestAuthorizationFor(String action) {
        /*
        this is (should be) called after userHasServicePairedDevice returns true. The
        BaseRequestProcessor to which this trigger delegates then sets a passcode in the state holder. So for this
        path there will only be a passcode in the state holder.
         */
        return new BaseRequestProcessor(action);
    }

    /**
     * For sms service authorization is requested by sending a custom sms message that includes a passcode to be entered into
     * the challenge field of the radius client. This processor is only requesting autorization meaning the user
     * previously paired a phone number with their profile.
     *
     * @param action
     * @param parameterizedMessage may include '{#}' macros with 0="LDS Church", 1=username, 2=action, 3=passcode
     * @return
     */
    public static TransitionProcessor sendTextMessage(String action, String parameterizedMessage) {
        /*
        this is (should be) called after userHasServicePairedDevice returns true. The
        BaseRequestProcessor to which this trigger delegates then sets a passcode in the state holder. So for this
        path there will only be a passcode in the state holder.
         */
        return new BaseRequestProcessor(action, new MessageFormat(parameterizedMessage));
    }

    private static class BaseRequestProcessor extends TransitionProcessor {

        /**
         * The action that will be specified in the message.
         */
        private String action;
        private MessageFormat msgFormatter = SmsService.Message; // defaults to static format

        /**
         * Constructor that uses the default message format.
         * @param actionMsg
         */
        private BaseRequestProcessor(String actionMsg) {
            this.action = actionMsg;
        }

        /**
         * Constructor allowing overriding of default message. The call to the formatter passes three values that may
         * be used in the message with via a pattern of '{#}' where # is one of the following:
         *
         * <pre>
         *     0 = organization name "LDS Church",
         *     1 = username as received from initial incoming RADIUS request,
         *     2 = action to be performed which is the value passed as actionMsg to this constructor,
         *     3 = the passcode being injected.
         * </pre>
         * @param actionMsg
         * @param format
         */
        private BaseRequestProcessor(String actionMsg, MessageFormat format) {
            this.action = actionMsg;
            if (format != null) {
                this.msgFormatter = format;
            }
        }

        @Override
        public void process(RequestInfo req, Context ctx, String message) {
            CloseableHttpClient client = HttpClients.custom()
                    .disableAutomaticRetries()
                    .disableRedirectHandling()
                    .setDefaultSocketConfig(
                            // ensures that if a server error drops the connection or doesn't
                            // respond we don't wait for the default 30 seconds of inactivity
                            // before TCP throwing a socket timeout error.
                            SocketConfig.custom().setSoTimeout(5000).build()
                    )
                    .build();

            HttpPost post = new HttpPost(SMS_SEND);
            post.addHeader(new BasicHeader("Accept", "application/json"));

            // add authn
            String usrColonToken = APP_USR + ":" + APP_PWD;
            String authHeaderVal = "Basic " + DatatypeConverter.printBase64Binary(usrColonToken.getBytes(Charset.defaultCharset()));
            post.addHeader(new BasicHeader("Authorization", authHeaderVal));

            ContentType ct = ContentType.create("application/json", "utf-8");

            String organization = "The LDS Church";
            String user = req.username;

            // generate the digits of the passcode
            StringBuilder passcode = new StringBuilder();
            for(int i=0; i<PasscodeDigits; i++) {
                passcode.append(numGen.nextInt(10)); // will gen int from 0 to 9 inclusive
            }
            // gen the parms for use in for message formatter
            Object[] parms = new Object[] {
                    organization,
                    user,
                    action,
                    passcode.toString()
            };

            // place pc in state holder so it will pass to client and then back to us via the state attribute
            setPasscodeInStateHolder(req.stateHolder, passcode.toString());

            // craft our sms text message
            StringBuilder sb = new StringBuilder()
                    .append('{')
                    .append(" \"message\" : \"")
                    .append(this.msgFormatter.format(parms))
                    .append("\",")
                    .append(" \"key\" : \"" + APP_CODE_KEY + "\",")
                    .append(" \"locale\" : \"en-US\",")
                    .append(" \"recipients\" : [{\"country\":\"USA\", \"number\" : \"" + req.devicePairingId + "\" }]")
                    .append("}");

            StringEntity payload = new StringEntity(sb.toString(), ct);
            post.setEntity(payload);

            // send it via the sms rest api
            CloseableHttpResponse response = null;
            try {
                response = client.execute(post);
            } catch (Throwable e) {
                e.printStackTrace();
                return;
            }
            int status = response.getStatusLine().getStatusCode();
            String msg = "" + status + " http Response code for " + SMS_SEND + ".";

            String body = null;
            try {
                body = readHttpComponentsJsonEntityAsString(response.getEntity());
                System.out.println("Service returned: " + body);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // ----- entered phone number has valid format trigger

    /**
     * Trigger that returns true if the submitted text DOES conforms to
     * E.164 (starts with a '+' character [and for prototype U.S. country code '1']). Also sets as the req.devicePairingId
     * for consumption by the BaseRequestProcessor nested class.
     *
     * Called when acquiring phone number to be paired with this user. Verifies that the submitted format conforms to
     * E.164 (starts with a '+' character [and for prototype U.S. country code '1']) and strips off the plus symbol and
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
                    req.devicePairingId = req.credential.substring(2); // trim off + and country code
                    setPhoneNumberInStateHolder(req.stateHolder, req.devicePairingId);
                    return true;
                }
                return false;
            }
        };
    }


    /**
     * Accepts an entity of content type "application/json" and returns its content extracted into a String.
     *
     * @param entity
     * @return
     */
    public static String readHttpComponentsJsonEntityAsString(HttpEntity entity) throws IOException {
        Header hdr = entity.getContentType();
        String type = hdr.getValue();
        if (!type.toLowerCase().startsWith("application/json")) {
            throw new IllegalArgumentException("Attempting to read text from application/json entity but found type " + type);
        }
        HeaderElement elm = hdr.getElements()[0]; // content-type header: formatted content with params so convert to header element
        NameValuePair csp = elm.getParameterByName("charset");
        String charSet = "utf-8"; // default
        if (csp != null) {
            charSet = csp.getValue();
        }
        StringBuffer sb = new StringBuffer();
        InputStream in = entity.getContent();
        InputStreamReader rdr = new InputStreamReader(in, charSet);
        char[] chars = new char[1024];
        int charsRead = 0;

        while (charsRead != -1) {
            sb.append(chars, 0, charsRead);
            charsRead = rdr.read(chars);
        }
        return sb.toString();
    }

    /**
     * Fulfills two requirements: validates the user has or does not have a pre-paired phone number, secondly, if a
     * number is already had the number is placed in req.devicePairingId for consumption by the BaseRequestProcessor
     * nested class.
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

    // ----- pairing request approved/failed triggers

    /**
     * Implementation of sms pairing request approved that backs the two triggers and answers yes if the submitted value
     * of the credential field (the challenge field) has the same value as the stateholder's property which is set to
     * the generated passcode prior to the challenge and is passed through and back via the radius state attribute.
     * @param req
     * @param ctx
     * @return
     */
    public static boolean _enteredPasscodeIsValid(RequestInfo req, Context ctx) {
        String submittedPc = req.credential;
        String origPc = getPasscodeFromStateHolder(req.stateHolder);
        return origPc != null && origPc.equals(submittedPc);
    }

    public static Trigger pairingRequestFailed() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return ! _enteredPasscodeIsValid(req, ctx);
            }
        };
    }

    public static Trigger pairingRequestWasApproved() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                if (_enteredPasscodeIsValid(req, ctx)) {
                    String phoneNum = getPhoneNumberFromStateHolder(req.stateHolder);
                    UsersProfile.addPairing(req.username, PAIRING_PREFIX + phoneNum);
                    return true;
                }
                return false;
            }
        };
    }

    // ----- stateholder property nested values setters/getters

    /**
     * Returns the passcode portion of the state holder's property value or null if no passcode is included.
     *
     * This method and the following three split the state holder's property value into two pieces. The first piece is
     * the passcode which is a string of characters '0' through '9'. The second is the phone number entered by the user
     * as the target of the message. Both must be passed to the radius client and received back to verify the value entered
     * by the user as the passcode was the same as what was sent to them via a message and to then persist the phone number
     * entered by them if this includes the initial pairing of that number with the user.
     *
     * Since we know the passcode to be numberic characters only it is the first value and is terminated by a ':'
     * character. Characters following the colon character, if any, are the phone number that is being verified.
     *
     * @param holder
     * @return
     */
    public static String getPasscodeFromStateHolder(StateHolder holder) {
        String prop = holder.getProperty();
        if (prop == null || prop.startsWith(STATEHOLDER_PROPERIES_SEPARATOR)) {
            return null;
        }
        String pc = prop.substring(0, prop.indexOf(STATEHOLDER_PROPERIES_SEPARATOR));
        return pc;
    }

    /**
     * Returns the phone number portion of the state holder's property value or null if no number is included.
     * See docs for getPasscodeFromStateHolder().
     *
     * @param holder
     * @return
     */
    public static String getPhoneNumberFromStateHolder(StateHolder holder) {
        String prop = holder.getProperty();
        if (prop == null || prop.endsWith(STATEHOLDER_PROPERIES_SEPARATOR)) {
            return null;
        }
        String num = prop.substring(prop.indexOf(STATEHOLDER_PROPERIES_SEPARATOR) + 1);
        return num;
    }

    /**
     * Sets the passcode portion of the state holder's property value. See docs for getPasscodeFromStateHolder().
     *
     * @param holder
     * @param passcode
     */
    public static void setPasscodeInStateHolder(StateHolder holder, String passcode) {
        /*
        No guarantee on when called. Property may be empty or already have the phone number which will be prefixed by
        the '|' character.
         */
        String prop = holder.getProperty();

        if (prop == null) {
            holder.setProperty(passcode + STATEHOLDER_PROPERIES_SEPARATOR);
        }
        else if (prop.startsWith(STATEHOLDER_PROPERIES_SEPARATOR)) {
            holder.setProperty(passcode + prop);
        }
    }

    /**
     * Sets the phone number portion of the state holder's property value. See docs for getPasscodeFromStateHolder().
     *
     * @param holder
     * @param phoneNum
     */
    public static void setPhoneNumberInStateHolder(StateHolder holder, String phoneNum) {
        /*
        No guarantee on when called. Property may be empty or already have the passcode which will be terminated by
        the '|' character.
         */
        String prop = holder.getProperty();

        if (prop == null) {
            holder.setProperty(STATEHOLDER_PROPERIES_SEPARATOR + phoneNum);
        }
        else if (prop.endsWith(STATEHOLDER_PROPERIES_SEPARATOR)) {
            holder.setProperty(prop + phoneNum);
        }
    }

    // ----- authN Req approved/failed triggers

    public static Trigger authNRequestWasApproved() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return _enteredPasscodeIsValid(req, ctx);
            }
        };
    }

    public static Trigger authNRequestWasDenied() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return ! _enteredPasscodeIsValid(req, ctx);
            }
        };
    }


}
