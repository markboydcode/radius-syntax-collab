package com.sun.identity.authentication.modules.radius.server.poc;


/**
 * Trigger that is triggered when the RequestInfo.credentials value holds the configured selection value. RequestInfo's
 * credentials value is populated by the incoming RADIUS request's Password attribute through which RADIUS challenge
 * answers are passed from the RADIUS client as a result of a previous RADIUS Access-Challenge response being sent from
 * this server to the client.
 *
 * Created by markboyd on 6/28/14.
 */
public class UserEnters {

    /**
     * The value configured to be compared to the RequestInfo.credential property to activate this trigger.
     */
    private String selection;

    /**
     * If true then trigger is true upon the user pressing the continue button with any value specified in the
     * challenge's answer field. In otherwords, a UserSelects.anything() will always return true for isTriggered().
     */
    private boolean acceptAnySelection = false;

    private UserEnters() {
        super();
    }

    /**
     * Returns a configured UserEnters trigger that is activated when the user's selection
     * visible via RequestInfo's credential value is not empty.
     *
     * @return
     */
    public static Trigger phrase() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return req.credential != null;
            }
        };
    }

    /**
     * Returns a configured UserEnters trigger that is activated when the user's selection
     * visible via RequestInfo's credential value is empty.
     *
     * @return
     */
    public static Trigger nothing() {
        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return req.credential == null;
            }
        };
    }

    public static Trigger noPassword() {

        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return req.credential == null || "".equals(req.credential);
            }
        };
    }

    public static Trigger aPassword() {

        return new Trigger() {

            @Override
            public boolean isTriggered(RequestInfo req, Context ctx) {
                return req.credential != null;
            }
        };
    }
}
