package com.sun.identity.authentication.modules.radius.server.poc;

/**
 * Trigger that is triggered when the RequestInfo.credentials value holds the configured selection value. RequestInfo's
 * credentials value is populated by the incoming RADIUS request's Password attribute through which RADIUS challenge
 * answers are passed from the RADIUS client as a result of a previous RADIUS Access-Challenge response being sent from
 * this server to the client.
 *
 * Created by markboyd on 6/28/14.
 */
public class UserSelects extends Trigger {

    /**
     * The value configured to be compared to the RequestInfo.credential property to activate this trigger.
     */
    private String selection;

    /**
     * If true then trigger is true upon the user pressing the continue button with any value specified in the
     * challenge's answer field. In otherwords, a UserSelects.anything() will always return true for isTriggered().
     */
    private boolean acceptAnySelection = false;

    private UserSelects() {
        super();
    }

    /**
     * Implements the trigger functionality outlined in the class javadoc.
     *
     * @param req
     * @return
     */
    @Override
    public boolean isTriggered(RequestInfo req, Context ctx) {
        return this.acceptAnySelection || this.selection.equals(req.credential);
    }

    /**
     * Chainable builder method returning a configured UserSelects trigger that is activated when the user's selection
     * visible via RequestInfo's credential value matches the configured selection value.
     *
     * @param selection
     * @return
     */
    public static UserSelects value(String selection) {
        UserSelects s = new UserSelects();
        s.selection = selection;
        return s;
    }

    /**
     * Chainable builder method returning a configured UserSelects trigger that is activated when the user's selection
     * visible via RequestInfo's credential value matches the configured selection value. Be sure to only configure this
     * for a Transition that is last in its list since it will be the catch all and will always be taken if evaluation
     * reaches it.
     *
     * @return
     */
    public static UserSelects anything() {
        UserSelects s = new UserSelects();
        s.acceptAnySelection = true;
        return s;
    }
}