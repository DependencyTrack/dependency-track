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
package org.dependencytrack.tasks;

import alpine.event.LdapSyncEvent;
import alpine.event.framework.Event;
import alpine.server.auth.SessionTokenService;
import alpine.server.tasks.LdapSyncTask;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.event.DefectDojoUploadEventAbstract;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.event.KennaSecurityUploadEventAbstract;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.VulnerabilityMetricsUpdateEvent;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.event.maintenance.PackageMetadataMaintenanceEvent;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityDatabaseMaintenanceEvent;
import org.dependencytrack.metrics.UpdatePortfolioMetricsWorkflow;
import org.dependencytrack.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.notification.ProcessScheduledNotificationsWorkflow;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ScheduledNotificationDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.pkgmetadata.ResolvePackageMetadataWorkflow;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.vulnerability.SyncVulnPolicyBundleWorkflow;
import org.dependencytrack.proto.internal.workflow.v1.MirrorVulnDataSourceArg;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationsWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.SyncVulnPolicyBundleArg;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.PackageMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.dependencytrack.vulndatasource.MirrorVulnDataSourceWorkflow;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.TaskUtil.getCronScheduleForTask;
import static org.dependencytrack.util.TaskUtil.getCronScheduleFromConfig;

/**
 * @since 5.0.0
 */
public final class TaskSchedulerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskSchedulerInitializer.class);

    private final Config config;
    private final TaskScheduler scheduler;

    TaskSchedulerInitializer(Config config, TaskScheduler scheduler) {
        this.config = config;
        this.scheduler = scheduler;
    }

    @SuppressWarnings("unused")
    public TaskSchedulerInitializer() {
        this(ConfigProvider.getConfig(), new TaskScheduler());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        if (!config.getOptionalValue(ConfigKeys.TASK_SCHEDULER_ENABLED, boolean.class).orElse(true)) {
            LOGGER.info("Not starting task scheduler because it is disabled");
            return;
        }

        LOGGER.info("Starting task scheduler");
        scheduler.start();

        final var dexEngine = (DexEngine) event.getServletContext().getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        final var pluginManager = (PluginManager) event.getServletContext().getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        scheduler
                .schedule(
                        "Package Metadata Maintenance",
                        getCronScheduleForTask(PackageMetadataMaintenanceTask.class),
                        () -> Event.dispatch(new PackageMetadataMaintenanceEvent()))
                .schedule(
                        "Defect Dojo Upload",
                        getCronScheduleForTask(DefectDojoUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(DEFECTDOJO_ENABLED)) {
                                    Event.dispatch(new DefectDojoUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "EPSS Mirror",
                        getCronScheduleForTask(EpssMirrorTask.class),
                        () -> Event.dispatch(new EpssMirrorEvent()),
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "Fortify SSC Upload",
                        getCronScheduleForTask(FortifySscUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(FORTIFY_SSC_ENABLED)) {
                                    Event.dispatch(new FortifySscUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "GitHub Advisories Mirror",
                        getCronScheduleFromConfig(config, "dt.task.git.hub.advisory.mirror.cron"),
                        () -> maybeCreateVulnDataSourceMirrorWorkflowRun(pluginManager, dexEngine, "github", "GITHUB"),
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "Internal Component Identification",
                        getCronScheduleForTask(InternalComponentIdentificationTask.class),
                        () -> Event.dispatch(new InternalComponentIdentificationEvent()))
                .schedule(
                        "Kenna Security Upload",
                        getCronScheduleForTask(KennaSecurityUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(KENNA_ENABLED)) {
                                    Event.dispatch(new KennaSecurityUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "LDAP Sync",
                        getCronScheduleForTask(LdapSyncTask.class),
                        () -> Event.dispatch(new LdapSyncEvent()),
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "Metrics Maintenance",
                        getCronScheduleForTask(MetricsMaintenanceTask.class),
                        () -> Event.dispatch(new MetricsMaintenanceEvent()))
                .schedule(
                        "NVD Mirror",
                        getCronScheduleFromConfig(config, "dt.task.nist.mirror.cron"),
                        () -> maybeCreateVulnDataSourceMirrorWorkflowRun(pluginManager, dexEngine, "nvd", "NVD"),
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "OSV Mirror",
                        getCronScheduleFromConfig(config, "dt.task.osv.mirror.cron"),
                        () -> maybeCreateVulnDataSourceMirrorWorkflowRun(pluginManager, dexEngine, "osv", "OSV"),
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "Package Metadata Resolution",
                        getCronScheduleFromConfig(config, "dt.task.package-metadata-resolution.cron"),
                        () -> {
                            dexEngine.createRun(
                                    new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                                            .withWorkflowInstanceId(ResolvePackageMetadataWorkflow.INSTANCE_ID));
                        })
                .schedule(
                        "Portfolio Metrics Update",
                        getCronScheduleFromConfig(config, "dt.task.portfolio-metrics-update.cron"),
                        () -> {
                            dexEngine.createRun(
                                    new CreateWorkflowRunRequest<>(UpdatePortfolioMetricsWorkflow.class)
                                            .withWorkflowInstanceId(UpdatePortfolioMetricsWorkflow.INSTANCE_ID));
                        })
                .schedule(
                        "Portfolio Vulnerability Analysis",
                        getCronScheduleForTask(VulnerabilityAnalysisTask.class),
                        () -> Event.dispatch(new PortfolioVulnerabilityAnalysisEvent()))
                .schedule(
                        "Project Maintenance",
                        getCronScheduleForTask(ProjectMaintenanceTask.class),
                        () -> Event.dispatch(new ProjectMaintenanceEvent()))
                .schedule(
                        "Tag Maintenance",
                        getCronScheduleForTask(TagMaintenanceTask.class),
                        () -> Event.dispatch(new TagMaintenanceEvent()))
                .schedule(
                        "Vulnerability Database Maintenance",
                        getCronScheduleForTask(VulnerabilityDatabaseMaintenanceTask.class),
                        () -> Event.dispatch(new VulnerabilityDatabaseMaintenanceEvent()))
                .schedule(
                        "Vulnerability Metrics Update",
                        getCronScheduleForTask(VulnerabilityMetricsUpdateTask.class),
                        () -> Event.dispatch(new VulnerabilityMetricsUpdateEvent()))
                .schedule(
                        "Vulnerability Policy Bundle Sync",
                        getCronScheduleFromConfig(config, "dt.task.vulnerability-policy-bundle-sync.cron"),
                        () -> {
                            if (config.getOptionalValue(ConfigKeys.VULNERABILITY_POLICY_BUNDLE_URL, String.class).isEmpty()) {
                                return;
                            }

                            dexEngine.createRun(
                                    new CreateWorkflowRunRequest<>(SyncVulnPolicyBundleWorkflow.class)
                                            .withWorkflowInstanceId("sync-vuln-policy-bundle:" + VulnerabilityPolicyDao.DEFAULT_BUNDLE_UUID)
                                            .withArgument(SyncVulnPolicyBundleArg.newBuilder()
                                                    .setBundleUuid(VulnerabilityPolicyDao.DEFAULT_BUNDLE_UUID.toString())
                                                    .build()));
                        },
                        /* triggerOnFirstRun */ true)
                .schedule(
                        "Expired Session Cleanup",
                        getCronScheduleFromConfig(config, "dt.task.expired-session-cleanup.cron"),
                        () -> new SessionTokenService().deleteExpiredSessions())
                .schedule(
                        "Scheduled Notification Dispatch",
                        getCronScheduleFromConfig(config, "dt.task.scheduled-notification-dispatch.cron"),
                        () -> {
                            final Set<String> ruleNames = withJdbiHandle(
                                    handle -> new ScheduledNotificationDao(handle)
                                            .getDueScheduledNotificationRuleNames());
                            if (ruleNames.isEmpty()) {
                                return;
                            }

                            dexEngine.createRun(
                                    new CreateWorkflowRunRequest<>(ProcessScheduledNotificationsWorkflow.class)
                                            .withWorkflowInstanceId(ProcessScheduledNotificationsWorkflow.INSTANCE_ID)
                                            .withArgument(ProcessScheduledNotificationsWorkflowArg.newBuilder()
                                                    .addAllRuleNames(ruleNames)
                                                    .build()));
                        })
                .schedule(
                        "Telemetry Submission",
                        getCronScheduleFromConfig(config, "dt.task.telemetry-submission.cron"),
                        new TelemetrySubmissionTask(HttpClient.INSTANCE, config),
                        /* triggerOnFirstRun */ true);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        LOGGER.info("Stopping task scheduler");
        scheduler.close();
    }

    private static void maybeCreateVulnDataSourceMirrorWorkflowRun(
            PluginManager pluginManager,
            DexEngine dexEngine,
            String dataSourceName,
            String sourceName) {
        final VulnDataSourceFactory factory;
        try {
            factory = pluginManager.getFactory(VulnDataSource.class, dataSourceName);
        } catch (NoSuchExtensionException e) {
            return;
        }

        if (!factory.isDataSourceEnabled()) {
            return;
        }

        dexEngine.createRun(
                new CreateWorkflowRunRequest<>(MirrorVulnDataSourceWorkflow.class)
                        .withWorkflowInstanceId("mirror-vuln-data-source:" + dataSourceName)
                        .withArgument(MirrorVulnDataSourceArg.newBuilder()
                                .setDataSourceName(dataSourceName)
                                .setSourceName(sourceName)
                                .build()));
    }

}
