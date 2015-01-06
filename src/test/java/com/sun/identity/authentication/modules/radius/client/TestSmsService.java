package com.sun.identity.authentication.modules.radius.client;

import com.sun.identity.authentication.modules.radius.State;
import com.sun.identity.authentication.modules.radius.server.poc.SmsService;
import com.sun.identity.authentication.modules.radius.server.poc.StateHolder;
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
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;

/**
 * Created by markboyd on 7/7/14.
 */
public class TestSmsService {

    public static final String SMS_BASE_URL = "https://ws-stage.ldschurch.org/ws/sms/v2.0/Services/rest/SmsService";
    public static final String SMS_SEND = SMS_BASE_URL + "/sendMessages";

    public static final String APP_USR = "multiFactorAuthentication";
    public static final String APP_PWD = "willYouVerifyWhoYouAreAgainPlease";
    public static final String APP_CODE_KEY = APP_USR;

    //@Test
    public void sendSmsText() throws ClassNotFoundException {
        URL cl = this.getClass().getClassLoader().getResource("org/apache/http/message/BasicLineFormatter.class");
        System.out.println(cl.toExternalForm());
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

        StringBuilder sb = new StringBuilder()
                .append('{')
                .append(" \"message\" : \"Does this work?\",")
                .append(" \"key\" : \"" + APP_CODE_KEY + "\",")
                .append(" \"locale\" : \"en-US\",")
                .append(" \"recipients\" : [{\"country\":\"USA\", \"number\" : \"8016640964\" }]")
                .append("}");

        StringEntity payload = new StringEntity(sb.toString(), ct);
        post.setEntity(payload);

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

    @Test
    public void testStateHolderPropParsing() {
        StateHolder h = new StateHolder("DONE"); // no property included
        Assert.assertNull(SmsService.getPasscodeFromStateHolder(h));
        Assert.assertNull(SmsService.getPhoneNumberFromStateHolder(h));

        h = new StateHolder("DONE|:123");
        Assert.assertNull(SmsService.getPasscodeFromStateHolder(h));
        Assert.assertEquals(SmsService.getPhoneNumberFromStateHolder(h), "123");

        h = new StateHolder("DONE|456:");
        Assert.assertEquals(SmsService.getPasscodeFromStateHolder(h), "456");
        Assert.assertNull(SmsService.getPhoneNumberFromStateHolder(h));

        h = new StateHolder("DONE|456:123");
        Assert.assertEquals(SmsService.getPasscodeFromStateHolder(h), "456");
        Assert.assertEquals(SmsService.getPhoneNumberFromStateHolder(h), "123");

        h = new StateHolder(State.DONE);
        SmsService.setPasscodeInStateHolder(h, "456");
        Assert.assertEquals(h.getProperty(), "456:");

        h = new StateHolder(State.DONE);
        SmsService.setPhoneNumberInStateHolder(h, "123");
        Assert.assertEquals(h.getProperty(), ":123");

        h = new StateHolder(State.DONE);
        SmsService.setPhoneNumberInStateHolder(h, "123");
        SmsService.setPasscodeInStateHolder(h, "456");
        Assert.assertEquals(h.getProperty(), "456:123");

        h = new StateHolder(State.DONE);
        SmsService.setPasscodeInStateHolder(h, "456");
        SmsService.setPhoneNumberInStateHolder(h, "123");
        Assert.assertEquals(h.getProperty(), "456:123");

    }
}
