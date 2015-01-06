package com.sun.identity.authentication.modules.radius.server.poc;

/**
 * Abstract parent of all processors that can be placed between state transitions to perform some function. For example,
 * a transition could be specified UserSelects subclass could have the following build method:
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
public abstract class TransitionProcessor {

    protected TransitionProcessor() {
    }

    public abstract void process(RequestInfo req, Context ctx, String message);
}
