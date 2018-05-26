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
import alpine.event.framework.Event;
import alpine.logging.Logger;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import org.owasp.dependencytrack.auth.Permissions;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.RepositoryType;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.util.ArrayList;
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
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Project.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Component.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, License.class));

        loadDefaultLicenses();
        loadDefaultPermissions();
        loadDefaultPersonas();
        loadDefaultRepositories();

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
            LOGGER.info("Synchronizing SPDX license definitions to datastore.");

            final SpdxLicenseDetailParser parser = new SpdxLicenseDetailParser();
            try {
                final List<License> licenses = parser.getLicenseDefinitions();
                for (License license : licenses) {
                    LOGGER.info("Synchronizing: " + license.getName());
                    qm.synchronizeLicense(license, false);
                }
            } catch (IOException e) {
                LOGGER.error("An error occurred during the parsing SPDX license definitions.");
                LOGGER.error(e.getMessage());
            }
            qm.commitSearchIndex(License.class);
        }
    }

    /**
     * Loads the default permissions
     */
    private void loadDefaultPermissions() {
        try (QueryManager qm = new QueryManager()) {
            if (qm.getPermissions().size() > 0) {
                return;
            }
            LOGGER.info("Adding default permissions to datastore.");
            for (Permissions permission : Permissions.values()) {
                qm.createPermission(permission.name(), permission.getDescription());
            }
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
            ManagedUser admin = qm.createManagedUser("admin", "Administrator", "admin@localhost",
                    new String(PasswordService.createHash("admin".toCharArray())), true, true, false);

            final Team sysadmins = qm.createTeam("Administrators", false);
            final Team managers = qm.createTeam("Portfolio Managers", false);
            final Team automation = qm.createTeam("Automation", true);

            List<Permission> fullList = qm.getPermissions();

            sysadmins.setPermissions(fullList);
            managers.setPermissions(getPortfolioManagersPermissions(fullList));
            automation.setPermissions(getAutomationPermissions(fullList));

            qm.persist(sysadmins);
            qm.persist(managers);
            qm.persist(automation);

            qm.addUserToTeam(admin, sysadmins);

            admin = qm.getObjectById(ManagedUser.class, admin.getId());
            admin.setPermissions(qm.getPermissions());
            qm.persist(admin);
        }
    }

    private List<Permission> getPortfolioManagersPermissions(List<Permission> fullList) {
        List<Permission> permissions = new ArrayList<>();
        for (Permission permission: fullList) {
            if (permission.getName().equals(Permissions.Constants.VIEW_PORTFOLIO) ||
                    permission.getName().equals(Permissions.Constants.PORTFOLIO_MANAGEMENT)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    private List<Permission> getAutomationPermissions(List<Permission> fullList) {
        List<Permission> permissions = new ArrayList<>();
        for (Permission permission: fullList) {
            if (permission.getName().equals(Permissions.Constants.VIEW_PORTFOLIO) ||
                    permission.getName().equals(Permissions.Constants.SCAN_UPLOAD) ||
                    permission.getName().equals(Permissions.Constants.BOM_UPLOAD)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    /**
     * Loads the default repositories
     */
    private void loadDefaultRepositories() {
        try (QueryManager qm = new QueryManager()) {
            if (qm.getAllRepositories().size() > 0) {
                return;
            }
            LOGGER.info("Adding default repositories to datastore.");
            qm.createRepository(RepositoryType.GEM, "rubygems.org", "https://rubygems.org/", true);
            qm.createRepository(RepositoryType.MAVEN, "central", "http://central.maven.org/maven2/", true);
            qm.createRepository(RepositoryType.MAVEN, "atlassian-public", "https://maven.atlassian.com/content/repositories/atlassian-public/", true);
            qm.createRepository(RepositoryType.MAVEN, "jboss-releases", "https://repository.jboss.org/nexus/content/repositories/releases/", true);
            qm.createRepository(RepositoryType.MAVEN, "clojars", "https://repo.clojars.org/", true);
            qm.createRepository(RepositoryType.MAVEN, "google-android", "https://maven.google.com/", true);
            qm.createRepository(RepositoryType.NPM, "npm-public-registry", "https://registry.npmjs.org/", true);
        }
    }

}
