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

import alpine.auth.PasswordService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.logging.Logger;
import alpine.model.ManagedUser;
import alpine.model.Team;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

public class DefaultObjectGenerator implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DefaultObjectGenerator.class);

    public void contextInitialized(ServletContextEvent event) {
        // Creates empty indexes on startup if indexes do not exist
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Project.class));
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Component.class));
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, License.class));

        loadDefaultLicenses();
        loadDefaultPersonas();

        try {
            new CweImporter().processCweDefinitions();
        } catch (Exception e) {
            LOGGER.error("Error adding CWEs to database");
            LOGGER.error(e.getMessage());
        }
    }

    public void contextDestroyed(ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

    /**
     * Loads the default licenses into the database if no license data exists.
     */
    private void loadDefaultLicenses() {
        try (QueryManager qm = new QueryManager()) {
            if (qm.getLicenses().getTotal() > 0) {
                return;
            }

            LOGGER.info("Adding default SPDX license definitions to datastore.");

            final SpdxLicenseDetailParser parser = new SpdxLicenseDetailParser();
            try {
                final List<License> licenses = parser.getLicenseDefinitions();
                for (License license : licenses) {
                    LOGGER.info("Added: " + license.getName());
                    qm.createLicense(license, false);
                }
            } catch (IOException | URISyntaxException e) {
                LOGGER.error("An error occurred during the parsing SPDX license definitions.");
                LOGGER.error(e.getMessage());
            }
            qm.commitSearchIndex(License.class);
        }
    }

    /**
     * Loads the default users and teams
     */
    private void loadDefaultPersonas() {
        try (QueryManager qm = new QueryManager()) {
            if (qm.getManagedUsers().size() > 0 && qm.getTeams().size() > 0) {
                return;
            }
            LOGGER.info("Adding default users and teams to datastore.");
            final ManagedUser admin = qm.createManagedUser("admin", new String(PasswordService.createHash("admin".toCharArray())));
            final Team defaultTeam = qm.createTeam("Default Team", true);
            qm.addUserToTeam(admin, defaultTeam);
        }
    }

}
