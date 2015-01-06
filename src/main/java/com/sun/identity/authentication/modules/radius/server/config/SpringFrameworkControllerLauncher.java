package com.sun.identity.authentication.modules.radius.server.config;

import com.sun.identity.log.Level;
import org.springframework.stereotype.Controller;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import java.util.logging.Logger;

/**
 * This class is used as the trigger to start the OpenAM Radius server service via SpringFramework's component-scan
 * directive in a servlet file. It pushes the ServletContext to the RuntimeServiceStarter.
 *
 * Created by markboyd on 11/9/14.
 */

@Controller
public class SpringFrameworkControllerLauncher implements ServletContextAware {
    private static final Logger cLog = Logger.getLogger(SpringFrameworkControllerLauncher.class.getName());

    @Override
    public void setServletContext(ServletContext sc) {
        try {
            cLog.log(Level.INFO, "---> " + this.getClass().getSimpleName() + " starting " +
                    RadiusServiceStarter.class.getSimpleName());
            RadiusServiceStarter.getInstance().startUp();
        }
        catch(Throwable t) {
            System.out.println("Oops. Problem here.");
            t.printStackTrace();
        }
    }
}
