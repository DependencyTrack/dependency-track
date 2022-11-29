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
package org.dependencytrack.search;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.server.auth.PasswordService;
import org.dependencytrack.RequirementsVerifier;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.*;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.persistence.CweImporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.defaults.DefaultLicenseGroupImporter;
import org.dependencytrack.util.NotificationUtil;

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
public class IndexInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(IndexInitializer.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing search indices");
        if (RequirementsVerifier.failedValidation()) {
            return;
        }

        if (!IndexManager.exists(IndexManager.IndexType.LICENSE)) {
            LOGGER.info("Dispatching event to reindex licenses");
            Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, License.class));
        }
        if (!IndexManager.exists(IndexManager.IndexType.PROJECT)) {
            LOGGER.info("Dispatching event to reindex projects");
            Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Project.class));
        }
        if (!IndexManager.exists(IndexManager.IndexType.COMPONENT)) {
            LOGGER.info("Dispatching event to reindex components");
            Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Component.class));
        }
        if (!IndexManager.exists(IndexManager.IndexType.VULNERABILITY)) {
            LOGGER.info("Dispatching event to reindex vulnerabilities");
            Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Vulnerability.class));
        }
        if (!IndexManager.exists(IndexManager.IndexType.VULNERABLESOFTWARE)) {
            LOGGER.info("Dispatching event to reindex vulnerablesoftware");
            Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, VulnerableSoftware.class));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

}
