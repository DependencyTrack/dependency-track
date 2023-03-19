/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package org.dependencytrack.persistence;

import alpine.Config;
import alpine.common.logging.Logger;
import org.h2.server.web.WebServlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletRegistration;
import java.util.Map;

public class H2WebConsoleInitializer implements ServletContextListener {
    private static final Logger LOGGER = Logger.getLogger(H2WebConsoleInitializer.class);

    private static final String H2_CONSOLE_ENABLED_INIT_PARAM = "h2.console.enabled";
    private static final String H2_CONSOLE_PATH_INIT_PARAM = "h2.console.path";

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        Config configuration = Config.getInstance();
        String databaseMode = configuration.getProperty(Config.AlpineKey.DATABASE_MODE);
        String databaseDriver = configuration.getProperty(Config.AlpineKey.DATABASE_DRIVER);
        Boolean h2ConsoleEnabled = Boolean.valueOf(event.getServletContext().getInitParameter(H2_CONSOLE_ENABLED_INIT_PARAM));
        // Misconfiguration check, if external database is used, no need to pointlessly expose the H2 console
        if ("external".equals(databaseMode) || !org.h2.Driver.class.getName().equals(databaseDriver) || !h2ConsoleEnabled) {
            LOGGER.debug("H2 web console will not be initialized since either database mode is external or database driver is not H2 or the console is simply disabled !");
            LOGGER.debug("Database mode : "+databaseMode);
            LOGGER.debug("Database driver : "+databaseDriver);
            LOGGER.debug("H2 web console enabled : "+h2ConsoleEnabled);
            return;
        }
        String h2ConsolePath = event.getServletContext().getInitParameter(H2_CONSOLE_PATH_INIT_PARAM);
        LOGGER.warn("Building and exposing H2 web servlet to "+h2ConsolePath);
        LOGGER.warn("It should only be enabled for development purposes to avoid security risks related to production data leak.");
        ServletContext servletContext = event.getServletContext();
        WebServlet h2WebServlet = new WebServlet();
        ServletRegistration.Dynamic registration = servletContext.addServlet("h2Console", h2WebServlet);
        registration.addMapping(h2ConsolePath+"/*");
        registration.setLoadOnStartup(1);
        // Production filter alteration : we rely here on the fact the Jetty server does not entirely respect Servlet 3.0 specs. See https://github.com/DependencyTrack/dependency-track/pull/2561
        // H2 Console uses local iframe
        servletContext.getFilterRegistration("CspFilter").getInitParameters().put("frame-ancestors","'self'");
        // Allow H2 web console path
        Map<String, String> whitelistUrlParams = servletContext.getFilterRegistration("WhitelistUrlFilter").getInitParameters();
        String allowUrls = whitelistUrlParams.get("allowUrls");
        if (allowUrls != null && !allowUrls.contains(h2ConsolePath)) {
            whitelistUrlParams.put("allowUrls", allowUrls+","+h2ConsolePath);
        }
        String forwardExcludes = whitelistUrlParams.get("forwardExcludes");
        if (forwardExcludes != null && !forwardExcludes.contains(h2ConsolePath)) {
            whitelistUrlParams.put("forwardExcludes", forwardExcludes+","+h2ConsolePath);
        }
    }
}
