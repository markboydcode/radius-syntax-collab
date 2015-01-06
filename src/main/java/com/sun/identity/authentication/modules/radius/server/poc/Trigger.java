package com.sun.identity.authentication.modules.radius.server.poc;

/**
 * Abstract parent of all triggers causing transitions between states. Subclasses must also implement domain specific
 * static builder methods for instantiating configured instances of their specific triggers. For example, a UserSelects
 * subclass could have the following build method:
 *
 * <pre>
 *     public static UserSelects value(String selection) {
 *         return new UserSelects(selection);
 *     }
 * </pre>
 *
 * This would enable configuring a Trigger via UserSelects("T") which is very readable and comprehensible.
 *
 * Created by markboyd on 6/28/14.
 */
public abstract class Trigger {

    protected Trigger() {
    }

    /**
     * Implementations MUST implement to support their functionality.
     * @param req
     * @param ctx
     * @return
     */
    public abstract boolean isTriggered(RequestInfo req, Context ctx);
}
