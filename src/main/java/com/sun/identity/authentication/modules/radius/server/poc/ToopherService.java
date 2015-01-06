package com.sun.identity.authentication.modules.radius.server.poc;

import com.toopher.AuthenticationStatus;
import com.toopher.PairingStatus;
import com.toopher.RequestError;
import com.toopher.ToopherAPI;

/**
 * Created by markboyd on 6/30/14.
 */
public class ToopherService {


    public static String toopherConsumerName = "LDS Church";
    public static String toopherConsumerKey = "KKpt7nSMkdVhyt7MEw";
    public static String toopherConsumerSecret = "js3sWNDJAzBpCRWhWFHtYy55jrBh88J8";



    /**
     * Creates processors that issues authorization request from toopher for the user for the specified action
     * (terminal in toopher lingo) and then places the authorization request id into the state holder for passing
     * through RADIUS to the next submission.
     *
     * @return
     */
    public static TransitionProcessor requestAuthorizationFor (final String what) {
        return new TransitionProcessor() {

            @Override
            public void process(RequestInfo req, Context ctx, String message) {
                AuthenticationStatus requestStatus = null;
                ctx.toopherApi = new ToopherAPI(toopherConsumerKey, toopherConsumerSecret);

                try {
                    // we can get here from two routes initial pairing in which the pairing id will be passed back to
                    // us via the RADIUS request State attribute or via previously stored pairing ids which will
                    // leave the pairingId on the req.devicePairingId set by the ToopherService.userHasServicePairedDevice()
                    // trigger.
                    String pid = req.devicePairingId; // takes precedence if available

                    if (pid == null) {
                        pid = req.stateHolder.getProperty();
                        System.out.println("   -- Request authentication of user " + req.username + " with State provided pairing ID '" + pid + "'");
                    }
                    else {
                        System.out.println("   -- Request authentication of user " + req.username + " with persisted pairing ID '" + pid + "'");
                    }
                    requestStatus = ctx.toopherApi.authenticate(pid, what);
                } catch (RequestError requestError) {
                    System.out.println("Unable to request authentication for " + req.username); // TODO handle this post POC
                    requestError.printStackTrace();
                    return;
                }
                req.stateHolder.setProperty(requestStatus.id);
                System.out.println("   -- authentication request ID is: " + requestStatus.id);

            }
        };
    }

    /**
     * Creates processor that takes the submitted phrase available via req.credential and issues pairing request from
     * toopher for the user and then places the pairing request id into the state holder for passing through RADIUS to
     * the next submission.
     *
     * @return
     */
    public static TransitionProcessor requestPairingOfDevice() {
        return new TransitionProcessor() {

            @Override
            public void process(RequestInfo req, Context ctx, String message) {
                PairingStatus requestStatus = null;
                ctx.toopherApi = new ToopherAPI(toopherConsumerKey, toopherConsumerSecret);
                try {
                    System.out.println("   -- Request pairing for " + req.username + " with phrase '" + req.credential + "' for key " +
                    toopherConsumerKey + " and name " + toopherConsumerName + " with secret " + toopherConsumerSecret);
                    requestStatus = ctx.toopherApi.pair(req.credential, req.username);
                } catch (RequestError requestError) {
                    /*
                    at some point handle this exception for when pairing phrase is not found:
                    com.toopher.RequestError: Request error
	at com.toopher.ToopherAPI.pair(Unknown Source)
	at com.toopher.ToopherAPI.pair(Unknown Source)
	at com.sun.identity.authentication.modules.radius.server.poc.ToopherService$2.process(ToopherService.java:66)
	at com.sun.identity.authentication.modules.radius.server.poc.Transition.execute(Transition.java:119)
	at com.sun.identity.authentication.modules.radius.server.poc.RadiusListener.listen(RadiusListener.java:260)
	at com.sun.identity.authentication.modules.radius.server.poc.RadiusListener.main(RadiusListener.java:280)
Caused by: org.apache.http.client.HttpResponseException: Not Found
	at com.toopher.ToopherAPI$1.handleResponse(Unknown Source)
	at com.toopher.ToopherAPI$1.handleResponse(Unknown Source)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:1070)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:1044)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:1035)
	at com.toopher.ToopherAPI.request(Unknown Source)
	at com.toopher.ToopherAPI.post(Unknown Source)

                     */
                    System.out.println("Unable to request pairing for " + req.username); // TODO handle this post POC
                    requestError.printStackTrace();
                    return;
                }
                System.out.println("   -- pairing request ID is: " + requestStatus.id);
                req.stateHolder.setProperty(requestStatus.id);
            }
        };
    }

    public static Trigger pairingRequestWasDenied() {
        return pairingRequestWasDeniedTrigger;
    }

    /**
     * Implementation of pairing request approved for Toopher service that backs the two triggers.
     *
     * @param req
     * @param ctx
     * @return
     */
    private static boolean _pairingRequestWasApproved(RequestInfo req, Context ctx) {
        ctx.toopherApi = new ToopherAPI(toopherConsumerKey, toopherConsumerSecret);
        getPairingStatus(req, ctx);
        return req.pairingWasEnabled;
    }

    private static Trigger pairingRequestWasApprovedTrigger = new Trigger() {

        @Override
        public boolean isTriggered(RequestInfo req, Context ctx) {
            return _pairingRequestWasApproved(req, ctx);
        }
    };

    private static Trigger pairingRequestWasDeniedTrigger = new Trigger() {

        @Override
        public boolean isTriggered(RequestInfo req, Context ctx) {
            return ! _pairingRequestWasApproved(req, ctx);
        }
    };

    public static Trigger pairingRequestWasApproved() {
        return pairingRequestWasApprovedTrigger;
    }

    private static void getPairingStatus(RequestInfo req, Context ctx) {
        if (! req.pairingStatusRetrieved) {
            try {
                System.out.println("  -- Testing pairing status for user '" + req.username + "' via ID '" + req.stateHolder.getProperty() + "'");
                PairingStatus pairingStatus = ctx.toopherApi.getPairingStatus(req.stateHolder.getProperty());
                req.pairingWasEnabled = pairingStatus.enabled;

                // persist the pairing
                if (req.pairingWasEnabled) {
                    UsersProfile.addPairing(req.username, req.stateHolder.getProperty());
                }
                req.pairingStatusRetrieved = true;
            } catch (RequestError requestError) {
                System.out.println("- Unable to test pairing for: " + req.username + " using phrase '" + req.credential + "'");
                requestError.printStackTrace();
                // TODO: probably need to send a reject here after POC
                return;
            }
            System.out.println("   -- pairing status enabled = " + req.pairingWasEnabled);
        }
    }

    public static Trigger authNRequestWasApproved() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                ctx.toopherApi = new ToopherAPI(toopherConsumerKey, toopherConsumerSecret);
                getAuthenticationStatus(req, ctx);
                return req.authenticationWasApproved;
            }
        };
    }

    private static void getAuthenticationStatus(RequestInfo req, Context ctx) {
        if (! req.authenticationStatusRetrieved) {
            try {
                System.out.println("  -- Testing authentication status for user '" + req.username + "' via pid '" + req.stateHolder.getProperty() + "'");
                req.authenticationWasApproved = ctx.toopherApi.getAuthenticationStatus(req.stateHolder.getProperty()).granted; // need to consider automated or not at some point
                req.authenticationStatusRetrieved = true;
            } catch (RequestError requestError) {
                System.out.println("- Unable to pair device for: " + req.username + " using phrase '" + req.credential + "'");
                requestError.printStackTrace();
                return;
                // TODO: probably need to send a reject here after POC
            }
            System.out.println("   -- authentication granted = " + req.authenticationWasApproved);
        }
    }

    public static Trigger authNRequestWasDenied() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                ctx.toopherApi = new ToopherAPI(toopherConsumerKey, toopherConsumerSecret);
                getAuthenticationStatus(req, ctx);
                return ! req.authenticationWasApproved;
            }
        };
    }

    /**
     * Trigger that returns true if a pairing exists that doesn't contain ':' since toopher was the first authorization
     * mechanism implemented and we didn't need to store any other pairings. When others were added I introduced prefixes
     * to the values for other mechanisms and left the toopher pairing values without one. And toopher pairing IDs don't
     * have a colon character so I can use that as the prefix delineator.
     */
    private static Trigger userHasServicePairedDeviceTrigger = new Trigger() {
        @Override
        public boolean isTriggered(RequestInfo req, Context ctx) {
            String pairing = UsersProfile.getPairings().getProperty(req.username);
            if (pairing != null && ! pairing.contains(":")) {
                req.devicePairingId = pairing;
                return true;
            }
            return false;
        }
    };

    public static Trigger userHasServicePairedDevice() {
        return userHasServicePairedDeviceTrigger;
    }
}

