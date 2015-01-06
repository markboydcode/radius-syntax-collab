package com.sun.identity.authentication.modules.radius.client;


//import com.twilio.sdk.TwilioRestClient;
//import com.twilio.sdk.TwilioRestException;
//import com.twilio.sdk.resource.factory.CallFactory;
//import com.twilio.sdk.resource.instance.Account;
//import com.twilio.sdk.resource.instance.Call;
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
 * Created by markboyd on 7/5/14.
 */
public class TestTwilioCallout {

    private static final String AcctSid = "ACa48f2316ff66d87e8d915fa2ba1cce78";
    private static final String AcctAuthToken = "149b3b88b54356c6449a1eff13034d34";

    private static final String TwilioApiBase = "https://api.twilio.com/2010-04-01/Accounts/" + AcctSid + "/Calls.json";
    private static final String TwilioOwnedNumber = "+1801-663-7825";
    private static final String TwimletsBase = "http://twimlets.com/echo?Twiml=";
    private static final int PasscodeDigits = 0;
    //private static final int PasscodeDigits = 4;
    private static final MessageFormat Message = contructMessageTemplate(PasscodeDigits);
    private static final Random numGen = new Random();

    private static MessageFormat contructMessageTemplate(int passcodeDigits) {
        StringBuilder sb = new StringBuilder()
                //.append("<Response><Say>Your passcode from {0} for {1} to {2} is</Say>");
            .append("<Response><Say>hello there boyds. i know you.</Say>");

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

    private static final String NumberToCall = "+1801-484-5635";
    //private static final String NumberToCall = "+1801-664-0964";

    private UrlEncodedFormEntity buildEntityBody(final List<NameValuePair> params) {
        UrlEncodedFormEntity entity;
        try {
            entity = new UrlEncodedFormEntity(params, "UTF-8");
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return entity;
    }


    //@Test
    public void test() throws IOException {

        HttpClientBuilder builder = HttpClients.custom()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setDefaultSocketConfig(
                        // ensures that if a server error drops the connection or doesn't
                        // respond we don't wait for the default 30 seconds of inactivity
                        // before TCP throwing a socket timeout error.
                        SocketConfig.custom().setSoTimeout(1000).build()
                );

        CloseableHttpClient client = builder.build();
        HttpPost post = new HttpPost(TwilioApiBase);

        // build www-url-form-encoded payload
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("From", TwilioOwnedNumber));
        params.add(new BasicNameValuePair("To", NumberToCall));
        params.add(new BasicNameValuePair("Url", getTwimlUrl()));

        post.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

        post.addHeader(new BasicHeader("Accept", "application/json"));
        post.addHeader(new BasicHeader("Accept-Charset", "utf-8"));

        String usrColonToken = AcctSid + ":" + AcctAuthToken;
        String authHeaderVal = "Basic " + DatatypeConverter.printBase64Binary(usrColonToken.getBytes(Charset.defaultCharset()));
        System.out.println("---> " + authHeaderVal);

        post.addHeader(new BasicHeader("Authorization", authHeaderVal));

        CloseableHttpResponse resp = client.execute(post);
        System.out.println("Response Code: " + resp.getStatusLine().getStatusCode());
    }

//    @Test
//    public void testCallWithClientLib() throws TwilioRestException, NoSuchMethodException {
//        // Create a rest client
//        final TwilioRestClient client = new TwilioRestClient(AcctSid, AcctAuthToken);
//
//        // Get the main account (The one we used to authenticate the client)
//        final Account mainAccount = client.getAccount();
//        final CallFactory callFactory = mainAccount.getCallFactory();
//
//        String twimlUrl = getTwimlUrl();
//
//
//        // now we have the constructed message, lets make the call
//        final Map<String, String> callParams = new HashMap<String, String>();
//        callParams.put("To", NumberToCall); // Replace with a valid phone number
//        callParams.put("From", TwilioOwnedNumber); // Replace with a valid phone number in your account
//        callParams.put("Url", twimlUrl);
//        final Call call = callFactory.create(callParams);
//        System.out.println(call.getSid());

        // Specifics of the rest API based upon traffic below that results from the above code

        // authorization header is base64 decoding of sid + ':' + auth-token
        // Accept: application/json
        // Accept: application/json
        // Content-Type: application/x-www-form-urlencoded; charset=UTF-8
        // Authorization: Basic QUNhNDhmMjMxNmZmNjZkODdlOGQ5MTVmYTJiYTFjY2U3ODoxNDliM2I4OGI1NDM1NmM2NDQ5YTFlZmYxMzAzNGQzNA==
        //
        // body: Url=http%3A%2F%2Ftwimlets.com%2Fecho%3FTwiml%3D%253CResponse%253E%253CSay%253EYour%2Bpasscode%2Bfrom%2BThe%2BL%2BD%2BS%2BChurch%2Bfor%2BMark%2BBoyd%2Bto%2Baccess%2BV%2BP%2BN%2Bis%253C%252FSay%253E%253CSay%253E6%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E5%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E3%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E9%253C%252FSay%253E%253C%252FResponse%253E&To=%2B1801-664-0964&From=%2B1801-663-7825
        //


        /*

        /Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/bin/java -ea -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.SimpleLog -Dorg.apache.commons.logging.simplelog.showdatetime=true -Dorg.apache.commons.logging.simplelog.log.org.apache.http=DEBUG -Dorg.apache.commons.logging.simplelog.log.org.apache.http.wire=DEBUG -Didea.launcher.port=7532 "-Didea.launcher.bin.path=/Applications/IntelliJ IDEA 13.app/bin" -Dfile.encoding=UTF-8 -classpath "/Applications/IntelliJ IDEA 13.app/plugins/testng/lib/testng-plugin.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/ant-javafx.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/dt.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/javafx-doclet.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/javafx-mx.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/jconsole.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/sa-jdi.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/lib/tools.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/charsets.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/deploy.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/htmlconverter.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/javaws.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/jce.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/jfr.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/jfxrt.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/JObjC.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/jsse.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/management-agent.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/plugin.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/resources.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/rt.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/dnsns.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/localedata.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/sunec.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/sunjce_provider.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/sunpkcs11.jar:/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home/jre/lib/ext/zipfs.jar:/Users/markboyd/svn/openam/openam/openam-authentication/openam-auth-radius/target/test-classes:/Users/markboyd/svn/openam/openam/openam-authentication/openam-auth-radius/target/classes:/Users/markboyd/git/toopher-java/Toopher.jar:/Users/markboyd/.m2/repository/org/apache/httpcomponents/httpclient/4.3.3/httpclient-4.3.3.jar:/Users/markboyd/.m2/repository/org/apache/httpcomponents/httpcore/4.3.2/httpcore-4.3.2.jar:/Users/markboyd/.m2/repository/commons-logging/commons-logging/1.1.3/commons-logging-1.1.3.jar:/Users/markboyd/.m2/repository/commons-codec/commons-codec/1.6/commons-codec-1.6.jar:/Users/markboyd/.m2/repository/com/twilio/sdk/twilio-java-sdk/3.4.5/twilio-java-sdk-3.4.5.jar:/Users/markboyd/.m2/repository/commons-lang/commons-lang/2.6/commons-lang-2.6.jar:/Users/markboyd/.m2/repository/com/googlecode/json-simple/json-simple/1.1/json-simple-1.1.jar:/Users/markboyd/.m2/repository/org/codehaus/jackson/jackson-mapper-asl/1.9.7/jackson-mapper-asl-1.9.7.jar:/Users/markboyd/.m2/repository/org/codehaus/jackson/jackson-core-asl/1.9.7/jackson-core-asl-1.9.7.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-core/12.0.0-SNAPSHOT/openam-core-12.0.0-20140723.011751-208.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-license-servlet/12.0.0-SNAPSHOT/openam-license-servlet-12.0.0-20140723.011751-115.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-license-core/12.0.0-SNAPSHOT/openam-license-core-12.0.0-20140723.011751-120.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-shared/12.0.0-SNAPSHOT/openam-shared-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/com/google/inject/guice/3.0/guice-3.0-no_aop.jar:/Users/markboyd/.m2/repository/javax/inject/javax.inject/1/javax.inject-1.jar:/Users/markboyd/.m2/repository/com/google/inject/extensions/guice-multibindings/3.0/guice-multibindings-3.0.jar:/Users/markboyd/.m2/repository/external/jss4/2007-08-11/jss4-2007-08-11.jar:/Users/markboyd/.m2/repository/org/json/json/20090211/json-20090211.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/json-fluent/2.2.4-SNAPSHOT/json-fluent-2.2.4-20140325.161240-3.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/forgerock-util/1.3.0/forgerock-util-1.3.0.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/forgerock-guice-core/1.0.1/forgerock-guice-core-1.0.1.jar:/Users/markboyd/.m2/repository/org/slf4j/slf4j-api/1.7.5/slf4j-api-1.7.5.jar:/Users/markboyd/.m2/repository/org/testng/testng/6.8.5/testng-6.8.5.jar:/Users/markboyd/.m2/repository/junit/junit/4.10/junit-4.10.jar:/Users/markboyd/.m2/repository/org/hamcrest/hamcrest-core/1.1/hamcrest-core-1.1.jar:/Users/markboyd/.m2/repository/org/beanshell/bsh/2.0b4/bsh-2.0b4.jar:/Users/markboyd/.m2/repository/com/beust/jcommander/1.27/jcommander-1.27.jar:/Users/markboyd/.m2/repository/org/yaml/snakeyaml/1.6/snakeyaml-1.6.jar:/Users/markboyd/.m2/repository/org/mockito/mockito-all/1.9.5/mockito-all-1.9.5.jar:/Users/markboyd/.m2/repository/com/googlecode/java-ipv6/java-ipv6/0.14/java-ipv6-0.14.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-entitlements/12.0.0-SNAPSHOT/openam-entitlements-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-coretoken/12.0.0-SNAPSHOT/openam-coretoken-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-rest/12.0.0-SNAPSHOT/openam-rest-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/javax/ws/rs/jsr311-api/1.1.1/jsr311-api-1.1.1.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-idsvcs-schema/12.0.0-SNAPSHOT/openam-idsvcs-schema-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/javax/xml/bind/jaxb-api/1.0.6/jaxb-api-1.0.6.jar:/Users/markboyd/.m2/repository/javax/xml/parsers/jaxp-api/1.4.2/jaxp-api-1.4.2.jar:/Users/markboyd/.m2/repository/com/sun/xml/bind/jaxb-impl/1.0.6/jaxb-impl-1.0.6.jar:/Users/markboyd/.m2/repository/com/sun/xml/bind/jaxb-libs/1.0.6/jaxb-libs-1.0.6.jar:/Users/markboyd/.m2/repository/com/sun/msv/datatype/xsd/xsdlib/20060615/xsdlib-20060615.jar:/Users/markboyd/.m2/repository/isorelax/isorelax/20030108/isorelax-20030108.jar:/Users/markboyd/.m2/repository/relaxngDatatype/relaxngDatatype/20020414/relaxngDatatype-20020414.jar:/Users/markboyd/.m2/repository/javax/xml/jaxrpc-api/1.1/jaxrpc-api-1.1.jar:/Users/markboyd/.m2/repository/com/sun/xml/rpc/jaxrpc-spi/1.1.3_01/jaxrpc-spi-1.1.3_01.jar:/Users/markboyd/.m2/repository/external/jaxrpc-impl/1.1.3_01-041406/jaxrpc-impl-1.1.3_01-041406.jar:/Users/markboyd/.m2/repository/external/webservices-api/2009-14-01/webservices-api-2009-14-01.jar:/Users/markboyd/.m2/repository/javax/mail/mail/1.4.5/mail-1.4.5.jar:/Users/markboyd/.m2/repository/javax/activation/activation/1.1/activation-1.1.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-mib-schema/12.0.0-SNAPSHOT/openam-mib-schema-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/external/jdmkrt/2007-01-10/jdmkrt-2007-01-10.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-xacml3-schema/12.0.0-SNAPSHOT/openam-xacml3-schema-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-ldap-utils/12.0.0-SNAPSHOT/openam-ldap-utils-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/org/forgerock/opendj/opendj-ldap-sdk/2.6.8/opendj-ldap-sdk-2.6.8.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/i18n-core/1.4.0/i18n-core-1.4.0.jar:/Users/markboyd/.m2/repository/org/glassfish/grizzly/grizzly-framework/2.3.4/grizzly-framework-2.3.4.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-annotations/12.0.0-SNAPSHOT/openam-annotations-12.0.0-20140723.011751-209.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/openam-license-manager-cli/12.0.0-SNAPSHOT/openam-license-manager-cli-12.0.0-20140723.011751-110.jar:/Users/markboyd/.m2/repository/org/forgerock/openam/oauth2-core/12.0.0-SNAPSHOT/oauth2-core-12.0.0-20140723.011751-82.jar:/Users/markboyd/.m2/repository/com/google/inject/extensions/guice-assistedinject/3.0/guice-assistedinject-3.0.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/json-web-token/2.2.4-SNAPSHOT/json-web-token-2.2.4-20140325.161240-3.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/json-resource-servlet/2.2.4-SNAPSHOT/json-resource-servlet-2.2.4-20140325.161240-3.jar:/Users/markboyd/.m2/repository/org/forgerock/commons/json-resource/2.2.4-SNAPSHOT/json-resource-2.2.4-20140325.161240-3.jar:/Users/markboyd/.m2/repository/com/sun/mail/javax.mail/1.5.1/javax.mail-1.5.1.jar:/Users/markboyd/.m2/repository/org/forgerock/opendj/opendj-server/2.6.0/opendj-server-2.6.0.jar:/Users/markboyd/.m2/repository/com/iplanet/jato/jato/2005-05-04/jato-2005-05-04.jar:/Users/markboyd/.m2/repository/com/sun/web/ui/cc/2008-08-08/cc-2008-08-08.jar:/Users/markboyd/.m2/repository/org/apache/click/click-extras/2.3.0/click-extras-2.3.0.jar:/Users/markboyd/.m2/repository/org/apache/click/click-nodeps/2.3.0/click-nodeps-2.3.0.jar:/Users/markboyd/.m2/repository/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar:/Users/markboyd/.m2/repository/commons-fileupload/commons-fileupload/1.2.2/commons-fileupload-1.2.2.jar:/Users/markboyd/.m2/repository/commons-io/commons-io/2.3/commons-io-2.3.jar:/Users/markboyd/.m2/repository/ognl/ognl/2.6.9/ognl-2.6.9.jar:/Users/markboyd/.m2/repository/org/apache/velocity/velocity/1.7/velocity-1.7.jar:/Users/markboyd/.m2/repository/commons-logging/commons-logging-api/1.1/commons-logging-api-1.1.jar:/Users/markboyd/.m2/repository/external/esapiport/2013-12-04/esapiport-2013-12-04.jar:/Users/markboyd/.m2/repository/com/sleepycat/je/5.0.73/je-5.0.73.jar:/Users/markboyd/.m2/repository/com/sun/jersey/jersey-bundle/1.1.1-ea/jersey-bundle-1.1.1-ea.jar:/Users/markboyd/.m2/repository/javax/servlet/jstl/1.1.2/jstl-1.1.2.jar:/Users/markboyd/.m2/repository/log4j/log4j/1.2.16/log4j-1.2.16.jar:/Users/markboyd/.m2/repository/xalan/xalan/2.7.1/xalan-2.7.1.jar:/Users/markboyd/.m2/repository/xalan/serializer/2.7.1/serializer-2.7.1.jar:/Users/markboyd/.m2/repository/xerces-J/xercesImpl/2.11.0/xercesImpl-2.11.0.jar:/Users/markboyd/.m2/repository/xerces-J/xml-serializer/2.11.0/xml-serializer-2.11.0.jar:/Users/markboyd/.m2/repository/external/publicsuffix/1.0.1/publicsuffix-1.0.1.jar:/Users/markboyd/.m2/repository/external/webservices-extra/2008-03-12/webservices-extra-2008-03-12.jar:/Users/markboyd/.m2/repository/external/webservices-extra-api/2003-09-04/webservices-extra-api-2003-09-04.jar:/Users/markboyd/.m2/repository/external/webservices-rt/2009-29-07/webservices-rt-2009-29-07.jar:/Applications/IntelliJ IDEA 13.app/plugins/testng/lib/testng.jar:/Applications/IntelliJ IDEA 13.app/lib/idea_rt.jar" com.intellij.rt.execution.application.AppMain org.testng.RemoteTestNGStarter -port 52046 -usedefaultlisteners false -socket52047 -temp /private/var/folders/5y/xss9pjsx55x_m5q9m0xrsb8r0000gn/T/idea_testng9128093166200988923.tmp
[TestNG] Running:
  /Users/markboyd/Library/Caches/IntelliJIdea13/temp-testng-customsuite.xml

msg: <Response><Say>Your passcode from The L D S Church for Mark Boyd to access V P N is</Say><Say>6</Say><Pause length='1'/><Say>5</Say><Pause length='1'/><Say>3</Say><Pause length='1'/><Say>9</Say></Response>
twiml url: http://twimlets.com/echo?Twiml=%3CResponse%3E%3CSay%3EYour+passcode+from+The+L+D+S+Church+for+Mark+Boyd+to+access+V+P+N+is%3C%2FSay%3E%3CSay%3E6%3C%2FSay%3E%3CPause+length%3D%271%27%2F%3E%3CSay%3E5%3C%2FSay%3E%3CPause+length%3D%271%27%2F%3E%3CSay%3E3%3C%2FSay%3E%3CPause+length%3D%271%27%2F%3E%3CSay%3E9%3C%2FSay%3E%3C%2FResponse%3E
2014/07/24 08:42:52:200 PDT [DEBUG] ThreadSafeClientConnManager - Get connection: {s}->https://api.twilio.com, timeout = 10000
2014/07/24 08:42:52:205 PDT [DEBUG] ConnPoolByRoute - [{s}->https://api.twilio.com] total kept alive: 0, total issued: 0, total allocated: 0 out of 20
2014/07/24 08:42:52:205 PDT [DEBUG] ConnPoolByRoute - No free connections [{s}->https://api.twilio.com][null]
2014/07/24 08:42:52:205 PDT [DEBUG] ConnPoolByRoute - Available capacity: 10 out of 10 [{s}->https://api.twilio.com][null]
2014/07/24 08:42:52:205 PDT [DEBUG] ConnPoolByRoute - Creating new connection [{s}->https://api.twilio.com]
2014/07/24 08:42:52:840 PDT [DEBUG] DefaultClientConnectionOperator - Connecting to api.twilio.com:443
2014/07/24 08:42:53:556 PDT [DEBUG] RequestAddCookies - CookieSpec selected: best-match
2014/07/24 08:42:53:570 PDT [DEBUG] RequestAuthCache - Auth cache not set in the context
2014/07/24 08:42:53:570 PDT [DEBUG] RequestTargetAuthentication - Target auth state: UNCHALLENGED
2014/07/24 08:42:53:571 PDT [DEBUG] RequestProxyAuthentication - Proxy auth state: UNCHALLENGED
2014/07/24 08:42:53:571 PDT [DEBUG] DefaultHttpClient - Attempt 1 to execute request
2014/07/24 08:42:53:571 PDT [DEBUG] DefaultClientConnection - Sending request: POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1
2014/07/24 08:42:53:572 PDT [DEBUG] wire -  >> "POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "X-Twilio-Client: java-3.4.5[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "User-Agent: twilio-java/3.4.5[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Accept: application/json[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Accept-Charset: utf-8[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Content-Length: 524[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Content-Type: application/x-www-form-urlencoded; charset=UTF-8[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Host: api.twilio.com[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "Connection: Keep-Alive[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] wire -  >> "[\r][\n]"
2014/07/24 08:42:53:573 PDT [DEBUG] headers - >> POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> X-Twilio-Client: java-3.4.5
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> User-Agent: twilio-java/3.4.5
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Accept: application/json
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Accept-Charset: utf-8
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Content-Length: 524
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Content-Type: application/x-www-form-urlencoded; charset=UTF-8
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Host: api.twilio.com
2014/07/24 08:42:53:574 PDT [DEBUG] headers - >> Connection: Keep-Alive
2014/07/24 08:42:53:575 PDT [DEBUG] wire -  >> "Url=http%3A%2F%2Ftwimlets.com%2Fecho%3FTwiml%3D%253CResponse%253E%253CSay%253EYour%2Bpasscode%2Bfrom%2BThe%2BL%2BD%2BS%2BChurch%2Bfor%2BMark%2BBoyd%2Bto%2Baccess%2BV%2BP%2BN%2Bis%253C%252FSay%253E%253CSay%253E6%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E5%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E3%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E9%253C%252FSay%253E%253C%252FResponse%253E&To=%2B1801-664-0964&From=%2B1801-663-7825"
2014/07/24 08:42:53:663 PDT [DEBUG] wire -  << "HTTP/1.1 401 UNAUTHORIZED[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "Date: Thu, 24 Jul 2014 15:42:54 GMT[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "Content-Type: application/json; charset=utf-8[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "Content-Length: 205[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "Connection: close[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "WWW-Authenticate: Basic realm="Twilio API"[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "X-Powered-By: AT-5000[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "X-Shenanigans: none[\r][\n]"
2014/07/24 08:42:53:666 PDT [DEBUG] wire -  << "[\r][\n]"
2014/07/24 08:42:53:667 PDT [DEBUG] DefaultClientConnection - Receiving response: HTTP/1.1 401 UNAUTHORIZED
2014/07/24 08:42:53:667 PDT [DEBUG] headers - << HTTP/1.1 401 UNAUTHORIZED
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << Date: Thu, 24 Jul 2014 15:42:54 GMT
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << Content-Type: application/json; charset=utf-8
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << Content-Length: 205
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << Connection: close
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << WWW-Authenticate: Basic realm="Twilio API"
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << X-Powered-By: AT-5000
2014/07/24 08:42:53:668 PDT [DEBUG] headers - << X-Shenanigans: none
2014/07/24 08:42:53:670 PDT [DEBUG] DefaultHttpClient - Authentication required
2014/07/24 08:42:53:670 PDT [DEBUG] DefaultHttpClient - api.twilio.com:443 requested authentication
2014/07/24 08:42:53:670 PDT [DEBUG] TargetAuthenticationStrategy - Authentication schemes in the order of preference: [negotiate, Kerberos, NTLM, Digest, Basic]
2014/07/24 08:42:53:671 PDT [DEBUG] TargetAuthenticationStrategy - Challenge for negotiate authentication scheme not available
2014/07/24 08:42:53:671 PDT [DEBUG] TargetAuthenticationStrategy - Challenge for Kerberos authentication scheme not available
2014/07/24 08:42:53:671 PDT [DEBUG] TargetAuthenticationStrategy - Challenge for NTLM authentication scheme not available
2014/07/24 08:42:53:671 PDT [DEBUG] TargetAuthenticationStrategy - Challenge for Digest authentication scheme not available
2014/07/24 08:42:53:683 PDT [DEBUG] DefaultHttpClient - Selected authentication options: [BASIC]
2014/07/24 08:42:53:684 PDT [DEBUG] DefaultClientConnection - Connection 0.0.0.0:52050<->174.129.254.101:443 closed
2014/07/24 08:42:53:685 PDT [DEBUG] DefaultClientConnectionOperator - Connecting to api.twilio.com:443
2014/07/24 08:42:54:085 PDT [DEBUG] RequestAddCookies - CookieSpec selected: best-match
2014/07/24 08:42:54:086 PDT [DEBUG] RequestAuthCache - Auth cache not set in the context
2014/07/24 08:42:54:086 PDT [DEBUG] RequestTargetAuthentication - Target auth state: CHALLENGED
2014/07/24 08:42:54:086 PDT [DEBUG] RequestTargetAuthentication - Generating response to an authentication challenge using basic scheme
2014/07/24 08:42:54:087 PDT [DEBUG] RequestProxyAuthentication - Proxy auth state: UNCHALLENGED
2014/07/24 08:42:54:087 PDT [DEBUG] DefaultHttpClient - Attempt 2 to execute request
2014/07/24 08:42:54:087 PDT [DEBUG] DefaultClientConnection - Sending request: POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "X-Twilio-Client: java-3.4.5[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "User-Agent: twilio-java/3.4.5[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "Accept: application/json[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "Accept-Charset: utf-8[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "Content-Length: 524[\r][\n]"
2014/07/24 08:42:54:087 PDT [DEBUG] wire -  >> "Content-Type: application/x-www-form-urlencoded; charset=UTF-8[\r][\n]"
2014/07/24 08:42:54:088 PDT [DEBUG] wire -  >> "Host: api.twilio.com[\r][\n]"
2014/07/24 08:42:54:088 PDT [DEBUG] wire -  >> "Connection: Keep-Alive[\r][\n]"
2014/07/24 08:42:54:088 PDT [DEBUG] wire -  >> "Authorization: Basic QUNhNDhmMjMxNmZmNjZkODdlOGQ5MTVmYTJiYTFjY2U3ODoxNDliM2I4OGI1NDM1NmM2NDQ5YTFlZmYxMzAzNGQzNA==[\r][\n]"
2014/07/24 08:42:54:088 PDT [DEBUG] wire -  >> "[\r][\n]"
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> POST /2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls.json HTTP/1.1
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> X-Twilio-Client: java-3.4.5
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> User-Agent: twilio-java/3.4.5
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Accept: application/json
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Accept-Charset: utf-8
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Content-Length: 524
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Content-Type: application/x-www-form-urlencoded; charset=UTF-8
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Host: api.twilio.com
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Connection: Keep-Alive
2014/07/24 08:42:54:088 PDT [DEBUG] headers - >> Authorization: Basic QUNhNDhmMjMxNmZmNjZkODdlOGQ5MTVmYTJiYTFjY2U3ODoxNDliM2I4OGI1NDM1NmM2NDQ5YTFlZmYxMzAzNGQzNA==
2014/07/24 08:42:54:089 PDT [DEBUG] wire -  >> "Url=http%3A%2F%2Ftwimlets.com%2Fecho%3FTwiml%3D%253CResponse%253E%253CSay%253EYour%2Bpasscode%2Bfrom%2BThe%2BL%2BD%2BS%2BChurch%2Bfor%2BMark%2BBoyd%2Bto%2Baccess%2BV%2BP%2BN%2Bis%253C%252FSay%253E%253CSay%253E6%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E5%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E3%253C%252FSay%253E%253CPause%2Blength%253D%25271%2527%252F%253E%253CSay%253E9%253C%252FSay%253E%253C%252FResponse%253E&To=%2B1801-664-0964&From=%2B1801-663-7825"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "HTTP/1.1 201 CREATED[\r][\n]"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "Date: Thu, 24 Jul 2014 15:42:55 GMT[\r][\n]"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "Content-Type: application/json; charset=utf-8[\r][\n]"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "Content-Length: 1016[\r][\n]"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "Connection: close[\r][\n]"
2014/07/24 08:42:54:492 PDT [DEBUG] wire -  << "X-Powered-By: AT-5000[\r][\n]"
2014/07/24 08:42:54:493 PDT [DEBUG] wire -  << "X-Shenanigans: none[\r][\n]"
2014/07/24 08:42:54:493 PDT [DEBUG] wire -  << "[\r][\n]"
2014/07/24 08:42:54:493 PDT [DEBUG] DefaultClientConnection - Receiving response: HTTP/1.1 201 CREATED
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << HTTP/1.1 201 CREATED
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << Date: Thu, 24 Jul 2014 15:42:55 GMT
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << Content-Type: application/json; charset=utf-8
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << Content-Length: 1016
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << Connection: close
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << X-Powered-By: AT-5000
2014/07/24 08:42:54:493 PDT [DEBUG] headers - << X-Shenanigans: none
2014/07/24 08:42:54:493 PDT [DEBUG] DefaultHttpClient - Authentication succeeded
2014/07/24 08:42:54:496 PDT [DEBUG] TargetAuthenticationStrategy - Caching 'basic' auth scheme for https://api.twilio.com:443
2014/07/24 08:42:54:508 PDT [DEBUG] wire -  << "{"sid": "CAb912f04d7f7c8856d1836be417df6953", "date_created": null, "date_updated": null, "parent_call_sid": null, "account_sid": "ACa48f2316ff66d87e8d915fa2ba1cce78", "to": "+18016640964", "to_formatted": "(801) 664-0964", "from": "+18016637825", "from_formatted": "(801) 663-7825", "phone_number_sid": "PN1a739cbbf7f37d82ff8ec5fe73066228", "status": "queued", "start_time": null, "end_time": null, "duration": null, "price": null, "price_unit": "USD", "direction": "outbound-api", "answered_by": null, "api_version": "2010-04-01", "annotation": null, "forwarded_from": null, "group_sid": null, "caller_name": null, "uri": "/2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls/CAb912f04d7f7c8856d1836be417df6953.json", "subresource_uris": {"notifications": "/2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls/CAb912f04d7f7c8856d1836be417df6953/Notifications.json", "recordings": "/2010-04-01/Accounts/ACa48f2316ff66d87e8d915fa2ba1cce78/Calls/CAb912f04d7f7c8856d1836be417df6953/Recordings.json"}}"
2014/07/24 08:42:54:508 PDT [DEBUG] DefaultClientConnection - Connection 0.0.0.0:52053<->174.129.254.101:443 shut down
2014/07/24 08:42:54:508 PDT [DEBUG] ThreadSafeClientConnManager - Released connection is not reusable.
2014/07/24 08:42:54:508 PDT [DEBUG] ConnPoolByRoute - Releasing connection [{s}->https://api.twilio.com][null]
2014/07/24 08:42:54:509 PDT [DEBUG] DefaultClientConnection - Connection 0.0.0.0:52053<->174.129.254.101:443 closed
2014/07/24 08:42:54:509 PDT [DEBUG] ConnPoolByRoute - Notifying no-one, there are no waiting threads
CAb912f04d7f7c8856d1836be417df6953

===============================================
Custom suite
Total tests run: 1, Failures: 0, Skips: 0
===============================================


Process finished with exit code 0



         */
//    }

    private String getTwimlUrl() {
        // build twiml for echo twimlet to return to handle the call flow
        String organization = "The L D S Church";
        String user = "Mark Boyd";
        String action = "access V P N";

        Object[] parms = new Object[3 + PasscodeDigits];
        parms[0] = organization;
        parms[1] = user;
        parms[2] = action;

        for(int i=0; i<PasscodeDigits; i++) {
            parms[i+3] = numGen.nextInt(10); // will gen int from 0 to 9 inclusive
        }

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
    private String utf8UrlEncode(String value) {
        try {
            return URLEncoder.encode(value, "utf-8");
        } catch (UnsupportedEncodingException e) {
            // ignore since should never happen given that utf-8 is fundamental to the jvm
        }
        return value; // if utf-8 isn't in the jvm we have no choice but to send it as-is
    }


}
