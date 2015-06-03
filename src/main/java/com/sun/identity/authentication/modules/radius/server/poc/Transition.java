/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015 LDS
 */
package com.sun.identity.authentication.modules.radius.server.poc;

import java.util.ArrayList;
import java.util.List;

import com.sun.identity.authentication.modules.radius.State;

/**
 * Represents a trigger-able transition between states and provides builder method to craft such transitions with their
 * triggers that can be evaluated via isTriggered() to determine if that transition should be taken. Created by markboyd
 * on 6/28/14.
 */
public class Transition {
    /**
     * The state to transition to if the trigger is triggered.
     */
    private State nextState;
    private List<Trigger> triggers = new ArrayList<Trigger>();
    private List<TransitionProcessor> processors = new ArrayList<TransitionProcessor>();

    /**
     * Default constructor. Private so builder methods are the only items that can change it.
     */
    private Transition() {

    }

    /**
     * Utility class used only during construction of Transitions to force IDE's to present only the when() method after
     * a Transition.to() method call.
     */
    public static class TriggerExpector {

        private final Transition transition;

        private TriggerExpector(Transition t) {
            this.transition = t;
        }

        public Transition when(Trigger trigger) {
            transition.triggers.add(trigger);
            return transition;
        }
    }

    /**
     * Enables multiple triggers being required to trigger a transition.
     *
     * @param trigger
     * @return
     */
    public Transition and(Trigger trigger) {
        this.triggers.add(trigger);
        return this;
    }

    /**
     * Ditto to after but these procs run after the transition has been made except that the order in which they are
     * added is the order in which they fire.
     *
     * @param proc
     * @return
     */
    /**
     * Adds a processor that runs as part of transitioning to a new state. The order in which processors are added is
     * the order in which they fire.
     *
     * @param proc
     * @return
     */
    public Transition then(TransitionProcessor proc) {
        this.processors.add(proc);
        return this;
    }

    /**
     * Returns true if the configured trigger for this transition is triggered.
     * 
     * @param req
     */
    public boolean isTriggered(RequestInfo req, Context ctx) {
        for (Trigger t : triggers) {
            boolean isActive = t.isTriggered(req, ctx);

            if (isActive == false) {
                return false;
            }
        }
        return true;
    }

    /**
     * Transition builder method that creates a transition setting its next state and returning the created transition
     * to support chaining of builder methods.
     *
     * @param nextState
     * @return
     */
    public static TriggerExpector to(State nextState) {
        Transition t = new Transition();
        t.nextState = nextState;
        TriggerExpector exp = new TriggerExpector(t);
        return exp;
    }

    /**
     * Runs all processors in the beforeProcs group if any, moves to the next state, then runs all the processors in the
     * afterProcs group if any, and returns the next state.
     *
     * @return
     * @param req
     * @param serverData
     * @param message
     */
    public void execute(RequestInfo req, Context serverData, String message) {
        for (TransitionProcessor p : processors) {
            p.process(req, serverData, message);
        }
    }

    /**
     * Gets the state to which this transition will lead.
     *
     * @return
     */
    public State getNextState() {
        return nextState;
    }
}
