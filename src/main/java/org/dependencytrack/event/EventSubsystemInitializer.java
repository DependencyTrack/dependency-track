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
package org.dependencytrack.event;

import alpine.event.LdapSyncEvent;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.logging.Logger;
import alpine.tasks.LdapSyncTask;
import org.dependencytrack.RequirementsVerifier;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.ClearComponentAnalysisCacheTask;
import org.dependencytrack.tasks.CloneProjectTask;
import org.dependencytrack.tasks.DefectDojoUploadTask;
import org.dependencytrack.tasks.FortifySscUploadTask;
import org.dependencytrack.tasks.GitHubAdvisoryMirrorTask;
import org.dependencytrack.tasks.IndexTask;
import org.dependencytrack.tasks.InternalComponentIdentificationTask;
import org.dependencytrack.tasks.KennaSecurityUploadTask;
import org.dependencytrack.tasks.MetricsUpdateTask;
import org.dependencytrack.tasks.NistMirrorTask;
import org.dependencytrack.tasks.TaskScheduler;
import org.dependencytrack.tasks.VulnDbSyncTask;
import org.dependencytrack.tasks.VulnerabilityAnalysisTask;
import org.dependencytrack.tasks.repositories.RepositoryMetaAnalyzerTask;
import org.dependencytrack.tasks.scanners.InternalAnalysisTask;
import org.dependencytrack.tasks.scanners.OssIndexAnalysisTask;
import org.dependencytrack.tasks.scanners.VulnDbAnalysisTask;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Initializes the event subsystem and configures event subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class EventSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(EventSubsystemInitializer.class);

    // Starts the EventService
    private static final EventService EVENT_SERVICE = EventService.getInstance();

    // Starts the SingleThreadedEventService
    private static final SingleThreadedEventService EVENT_SERVICE_ST = SingleThreadedEventService.getInstance();

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing asynchronous event subsystem");

        if (RequirementsVerifier.failedValidation()) {
            return;
        }
        EVENT_SERVICE.subscribe(BomUploadEvent.class, BomUploadProcessingTask.class);
        EVENT_SERVICE.subscribe(LdapSyncEvent.class, LdapSyncTask.class);
        EVENT_SERVICE.subscribe(InternalAnalysisEvent.class, InternalAnalysisTask.class);
        EVENT_SERVICE.subscribe(OssIndexAnalysisEvent.class, OssIndexAnalysisTask.class);
        EVENT_SERVICE.subscribe(GitHubAdvisoryMirrorEvent.class, GitHubAdvisoryMirrorTask.class);
        EVENT_SERVICE.subscribe(VulnDbSyncEvent.class, VulnDbSyncTask.class);
        EVENT_SERVICE.subscribe(VulnDbAnalysisEvent.class, VulnDbAnalysisTask.class);
        EVENT_SERVICE.subscribe(VulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.subscribe(PortfolioVulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        EVENT_SERVICE.subscribe(MetricsUpdateEvent.class, MetricsUpdateTask.class);
        EVENT_SERVICE.subscribe(CloneProjectEvent.class, CloneProjectTask.class);
        EVENT_SERVICE.subscribe(FortifySscUploadEventAbstract.class, FortifySscUploadTask.class);
        EVENT_SERVICE.subscribe(DefectDojoUploadEventAbstract.class, DefectDojoUploadTask.class);
        EVENT_SERVICE.subscribe(KennaSecurityUploadEventAbstract.class, KennaSecurityUploadTask.class);
        EVENT_SERVICE.subscribe(InternalComponentIdentificationEvent.class, InternalComponentIdentificationTask.class);
        EVENT_SERVICE.subscribe(ClearComponentAnalysisCacheEvent.class, ClearComponentAnalysisCacheTask.class);

        EVENT_SERVICE_ST.subscribe(IndexEvent.class, IndexTask.class);
        EVENT_SERVICE_ST.subscribe(NistMirrorEvent.class, NistMirrorTask.class);

        TaskScheduler.getInstance();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down asynchronous event subsystem");
        TaskScheduler.getInstance().shutdown();

        EVENT_SERVICE.unsubscribe(BomUploadProcessingTask.class);
        EVENT_SERVICE.unsubscribe(LdapSyncTask.class);
        EVENT_SERVICE.unsubscribe(InternalAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(OssIndexAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(GitHubAdvisoryMirrorTask.class);
        EVENT_SERVICE.unsubscribe(VulnDbSyncTask.class);
        EVENT_SERVICE.unsubscribe(VulnDbAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(RepositoryMetaAnalyzerTask.class);
        EVENT_SERVICE.unsubscribe(MetricsUpdateTask.class);
        EVENT_SERVICE.unsubscribe(CloneProjectTask.class);
        EVENT_SERVICE.unsubscribe(FortifySscUploadTask.class);
        EVENT_SERVICE.unsubscribe(DefectDojoUploadTask.class);
        EVENT_SERVICE.unsubscribe(KennaSecurityUploadTask.class);
        EVENT_SERVICE.unsubscribe(InternalComponentIdentificationTask.class);
        EVENT_SERVICE.shutdown();

        EVENT_SERVICE_ST.unsubscribe(IndexTask.class);
        EVENT_SERVICE_ST.unsubscribe(NistMirrorTask.class);
        EVENT_SERVICE_ST.shutdown();
    }
}
