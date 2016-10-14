/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.persistence;

import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.ConfigItem;
import org.owasp.dependencytrack.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.h2.tools.Server;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.sql.SQLException;

public class LocalPersistenceInitializer implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(LocalPersistenceInitializer.class);
    private static Server dbServer;

    public void contextInitialized(ServletContextEvent event) {
        startDbServer();
    }

    public void contextDestroyed(ServletContextEvent event) {
        stopDbServer();
    }

    private void startDbServer() {
        String mode = Config.getInstance().getProperty(ConfigItem.DATABASE_MODE);
        int port = Config.getInstance().getPropertyAsInt(ConfigItem.DATABASE_PORT);

        if (StringUtils.isEmpty(mode) || !(mode.equals("server") || mode.equals("embedded"))) {
            logger.error("Database mode not specified. Expected values are 'server' or 'embedded'");
        }

        if (dbServer != null || mode.equals("embedded")) {
            return;
        }
        String[] args = new String[]{
                "-tcp",
                "-tcpPort", String.valueOf(port),
                "-tcpAllowOthers"
        };
        try {
            logger.info("Attempting to start database service");
            dbServer = Server.createTcpServer(args).start();
            logger.info("Database service started");
        } catch (SQLException e) {
            logger.error("Unable to start database service: " + e.getMessage());
            stopDbServer();
            System.exit(1);
        }
    }

    private void stopDbServer() {
        logger.info("Shutting down database service");
        if (dbServer != null)
            dbServer.shutdown();
    }

}