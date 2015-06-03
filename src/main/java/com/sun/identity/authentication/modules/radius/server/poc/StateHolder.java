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

import com.sun.identity.authentication.modules.radius.State;

/**
 * This class helps keep track of which state in the authentication process we are in and any parameters that get passed
 * via the RADIUS state attribute to the client and handed back to us. It also encapsulates how to generate the
 * attribute's value including parameters and then pull them back out of such value when it is passed back to us from
 * the client. Created by markboyd on 6/28/14.
 */
public class StateHolder {

    private String property = null;
    private State state = null;

    /**
     * Decomposes the MultiFactorAuthState and optional value from a raw RADIUS State Attribute value.
     *
     * @param radiusStateAttributeValue
     */
    public StateHolder(String radiusStateAttributeValue) {
        int idx = radiusStateAttributeValue.indexOf('|');

        if (idx != -1) {
            String stateKey = radiusStateAttributeValue.substring(0, idx);
            this.state = State.valueOf(stateKey);
            this.property = radiusStateAttributeValue.substring(idx + 1);
            System.out.println("   -- STATE received: " + radiusStateAttributeValue + " --> " + this.state + " / "
                    + this.property);
        } else {
            this.state = State.valueOf(radiusStateAttributeValue);
            System.out.println("   -- STATE received: " + radiusStateAttributeValue + " --> " + this.state + " / "
                    + this.property);
        }
    }

    /**
     * Creates an instance with the specified MultiFactorAuthState.
     *
     * @param state
     */
    public StateHolder(State state) {
        this.state = state;
    }

    /**
     * Generates the value for the RADIUS State attribute formatted to be consumed by the constructor that takes this
     * same string to re-instantiate this instance when sent back to use by the RADIUS client.
     *
     * @return
     */
    public String toRadiusValue() {
        StringBuilder s = new StringBuilder().append(this.state.name());
        if (this.property != null) {
            s.append('|');
            s.append(property);
        }
        return s.toString();
    }

    public void setProperty(String value) {
        this.property = value;
    }

    public String getProperty() {
        return this.property;
    }

    public State getState() {
        return this.state;
    }

    /**
     * Sets the state to a new value.
     *
     * @param nextState
     */
    public void setState(State nextState) {
        this.state = nextState;
    }
}
