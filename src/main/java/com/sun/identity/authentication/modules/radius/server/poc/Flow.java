package com.sun.identity.authentication.modules.radius.server.poc;

import com.sun.identity.authentication.modules.radius.State;

import java.util.HashMap;
import java.util.Map;

/**
 * Holder of states and their configurations including flows from each via transitions. This is where we define the
 * state machine of the authentication process. A flow has a state, a (possibly empty) text message
 * (used in a RADIUS Access-Challenge response when such is issued when that state is the current state), and zero or
 * more Transitions. The current state defaults to STARTING if an incoming RADIUS request has no State attribute.
 * Otherwise, the current state is set to the state specified in the request. Then the set of configured transitions is
 * scanned to find the first who's trigger is active. If processing must take place before the transition occurs the
 * transition is configured to run after such processors. Likewise, other processors can be configured to run after the
 * transition to the new state has taken place. Various Trigger builders are available along with various
 * TransitionProcess builders.
 *
 *
 * Created by markboyd on 7/24/14.
 */
public class Flow {
    private Map<State, StateCfg> myFlows = new HashMap<State, StateCfg>();
    private State defaultState;

    public Flow() {
    }

    public Flow addDefaultState(State state) {
        this.defaultState = state;
        return this;
    }

    public Flow add(State s, String message, Transition... transitions) {
        myFlows.put(s, new StateCfg(message, transitions));
        return this;
    }

    public State getDefaultState() {
        return this.defaultState;
    }

    /**
     * Get the configured message and transitions for the given state or null if not found.
     *
     * @param state
     * @return
     */
    public StateCfg getConfig(State state) {
        return myFlows.get(state);
    }

    public static class StateCfg {
        private String message;
        private Transition[] transitions;

        private StateCfg(String message, Transition[] transitions) {
            this.message = message;
            this.transitions = transitions;
        }

        public Transition[] getTransitions() {
            return this.transitions;
        }

        public String getMessage() {
            return this.message;
        }
    }
}
