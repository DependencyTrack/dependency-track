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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event;

import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.event.maintenance.PackageMetadataMaintenanceEvent;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityDatabaseMaintenanceEvent;
import org.dependencytrack.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.tasks.DefectDojoUploadTask;
import org.dependencytrack.tasks.EpssMirrorTask;
import org.dependencytrack.tasks.FortifySscUploadTask;
import org.dependencytrack.tasks.InternalComponentIdentificationTask;
import org.dependencytrack.tasks.KennaSecurityUploadTask;
import org.dependencytrack.tasks.VulnerabilityAnalysisTask;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.PackageMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

import static java.util.Objects.requireNonNull;

/**
 * Initializes the event subsystem and configures event subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class EventSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(EventSubsystemInitializer.class);

    private final Config config;
    private final EventService eventService;
    private final SingleThreadedEventService singleThreadedEventService;

    EventSubsystemInitializer(
            Config config,
            EventService eventService,
            SingleThreadedEventService singleThreadedEventService) {
        this.config = config;
        this.eventService = eventService;
        this.singleThreadedEventService = singleThreadedEventService;
    }

    @SuppressWarnings("unused") // Used by servlet context.
    public EventSubsystemInitializer() {
        this(ConfigProvider.getConfig(), EventService.getInstance(), SingleThreadedEventService.getInstance());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing asynchronous event subsystem");

        final var dexEngine = (DexEngine) event.getServletContext().getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        final var secretManager = (SecretManager) event.getServletContext().getAttribute(SecretManager.class.getName());
        requireNonNull(secretManager, "secretManager has not been initialized");

        eventService.subscribe(
                PortfolioVulnerabilityAnalysisEvent.class,
                new VulnerabilityAnalysisTask(dexEngine));
        eventService.subscribe(VulnerabilityMetricsUpdateEvent.class, new VulnerabilityMetricsUpdateTask());
        eventService.subscribe(FortifySscUploadEventAbstract.class, new FortifySscUploadTask(HttpClient.INSTANCE, secretManager));
        eventService.subscribe(DefectDojoUploadEventAbstract.class, new DefectDojoUploadTask(HttpClient.INSTANCE, secretManager));
        eventService.subscribe(KennaSecurityUploadEventAbstract.class, new KennaSecurityUploadTask(HttpClient.INSTANCE, secretManager));
        eventService.subscribe(InternalComponentIdentificationEvent.class, new InternalComponentIdentificationTask());
        eventService.subscribe(EpssMirrorEvent.class, new EpssMirrorTask(HttpClient.INSTANCE));
        // Execute maintenance tasks on the single-threaded event service.
        // This way, they are not blocked by, and don't block, actual processing tasks on the main event service.
        singleThreadedEventService.subscribe(PackageMetadataMaintenanceEvent.class, new PackageMetadataMaintenanceTask());
        singleThreadedEventService.subscribe(MetricsMaintenanceEvent.class, new MetricsMaintenanceTask());
        singleThreadedEventService.subscribe(TagMaintenanceEvent.class, new TagMaintenanceTask());
        singleThreadedEventService.subscribe(VulnerabilityDatabaseMaintenanceEvent.class, new VulnerabilityDatabaseMaintenanceTask());
        singleThreadedEventService.subscribe(ProjectMaintenanceEvent.class, new ProjectMaintenanceTask());
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        LOGGER.info("Shutting down asynchronous event subsystem");

        final var drainTimeout = config
                .getOptionalValue(ConfigKeys.WORKER_POOL_DRAIN_TIMEOUT_DURATION, Duration.class)
                .orElse(Duration.ofSeconds(30));

        eventService.unsubscribe(VulnerabilityAnalysisTask.class);
        eventService.unsubscribe(VulnerabilityMetricsUpdateTask.class);
        eventService.unsubscribe(FortifySscUploadTask.class);
        eventService.unsubscribe(DefectDojoUploadTask.class);
        eventService.unsubscribe(KennaSecurityUploadTask.class);
        eventService.unsubscribe(InternalComponentIdentificationTask.class);
        eventService.unsubscribe(EpssMirrorTask.class);
        try {
            eventService.shutdown(drainTimeout);
        } catch (TimeoutException e) {
            LOGGER.warn("Failed to shut down event service", e);
        }

        singleThreadedEventService.unsubscribe(PackageMetadataMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(MetricsMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(TagMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(VulnerabilityDatabaseMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(ProjectMaintenanceTask.class);
        try {
            singleThreadedEventService.shutdown(drainTimeout);
        } catch (TimeoutException e) {
            LOGGER.warn("Failed to shut down single-threaded event service", e);
        }
    }
}
