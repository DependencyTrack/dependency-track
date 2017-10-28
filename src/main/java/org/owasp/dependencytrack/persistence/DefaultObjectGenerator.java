/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
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

/**
 * Creates default objects on an empty database.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DefaultObjectGenerator implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DefaultObjectGenerator.class);

    /**
     * {@inheritDoc}
     */
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

    /**
     * {@inheritDoc}
     */
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
