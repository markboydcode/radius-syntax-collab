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
 * Portions Copyrighted [2011] [ForgeRock AS]
 * Portions Copyrighted [2015] [Intellectual Reserve, Inc (IRI)]
 */
package com.sun.identity.authentication.modules.radius.client;


import java.util.Enumeration;
import java.util.Vector;

/**
 * Holder of the attribute instances in an instance of the {@link com.sun.identity.authentication.modules.radius.client
 * .Packet} type which is the superclass of all radius packet types. Maintains the order in which attributes are added.
 */
public class AttributeSet {
    /**
     * Holder of the attribute instances.
     */
    private Vector attrs = new Vector();

    /**
     * Constructor.
     */
    public AttributeSet() {
    }

    /**
     * Adds an attribute instance to the container.
     *
     * @param attr an attribute instance to be appended to the set
     */
    public void addAttribute(Attribute attr) {
        attrs.addElement(attr);
    }

    /**
     * Indicates the number of attributes held in the container.
     *
     * @return the number of contained attribute instances
     */
    public int size() {
        return attrs.size();
    }

    /**
     * Returns a legacy {@link java.util.Enumeration} for enumerating over the the contained attribute instances.
     *
     * @return an {@link java.util.Enumeration} object for enumerating over the set of attribute instances.
     */
    public Enumeration getAttributes() {
        return attrs.elements();
    }

    /**
     * Returns the first occurrence of an attribute instance of the specified type code.
     *
     * @param type the attribute type code to be searched for in the set of attributes in order of injection
     * @return the first attribute instance incurred having the given type code or null if none is found.
     */
    public Attribute getAttributeByType(int type) {
        int l = attrs.size();
        for (int i = 0; i < l; i++) {
            Attribute attr = getAttributeAt(i);
            if (attr.getType() == type) {
                return attr;
            }
        }
        return null;
    }

    /**
     * Returns the attribute instance at the indicated index location.
     *
     * @param pos the position of the attribute instance to be retrieved.
     * @return the instance of the attribute being retrieved
     */
    public Attribute getAttributeAt(int pos) {
        return (Attribute) attrs.elementAt(pos);
    }
}
