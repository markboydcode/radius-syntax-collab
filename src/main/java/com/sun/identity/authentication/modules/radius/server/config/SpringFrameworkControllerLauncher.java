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
package com.sun.identity.authentication.modules.radius.server.config;

import java.util.logging.Logger;

import javax.servlet.ServletContext;

import org.springframework.stereotype.Controller;
import org.springframework.web.context.ServletContextAware;

import com.sun.identity.log.Level;

/**
 * This class is used as the trigger to start the OpenAM Radius server service via SpringFramework's component-scan
 * directive in a servlet file. It pushes the ServletContext to the RuntimeServiceStarter. Created by markboyd on
 * 11/9/14.
 */

@Controller
public class SpringFrameworkControllerLauncher implements ServletContextAware {
    private static final Logger cLog = Logger.getLogger(SpringFrameworkControllerLauncher.class.getName());

    @Override
    public void setServletContext(ServletContext sc) {
        try {
            cLog.log(
                    Level.INFO,
                    "---> " + this.getClass().getSimpleName() + " starting "
                            + RadiusServiceStarter.class.getSimpleName());
            RadiusServiceStarter.getInstance().startUp();
        } catch (Throwable t) {
            System.out.println("Oops. Problem here.");
            t.printStackTrace();
        }
    }
}
