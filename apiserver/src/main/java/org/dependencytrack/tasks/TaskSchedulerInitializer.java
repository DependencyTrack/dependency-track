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

import alpine.server.auth.SessionTokenService;
import com.github.kagkarlsson.scheduler.CurrentlyExecuting;
import com.github.kagkarlsson.scheduler.Scheduler;
import com.github.kagkarlsson.scheduler.event.AbstractSchedulerListener;
import com.github.kagkarlsson.scheduler.stats.MicrometerStatsRegistry;
import com.github.kagkarlsson.scheduler.stats.StatsRegistryAdapter;
import com.github.kagkarlsson.scheduler.task.ExecutionComplete;
import com.github.kagkarlsson.scheduler.task.helper.RecurringTask;
import com.github.kagkarlsson.scheduler.task.helper.Tasks;
import com.github.kagkarlsson.scheduler.task.schedule.Schedule;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.metrics.UpdatePortfolioMetricsWorkflow;
import org.dependencytrack.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.notification.ProcessScheduledNotificationsWorkflow;
import org.dependencytrack.persistence.jdbi.ScheduledNotificationDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.pkgmetadata.ResolvePackageMetadataWorkflow;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.vulnerability.SyncVulnPolicyBundleWorkflow;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationsWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.SyncVulnPolicyBundleArg;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.PackageMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.dependencytrack.vulndatasource.VulnDataSourceMirrorService;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.TaskUtil.getCronScheduleForTask;
import static org.dependencytrack.util.TaskUtil.getCronScheduleFromConfig;

/**
 * @since 5.0.0
 */
public final class TaskSchedulerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskSchedulerInitializer.class);

    private final Config config;
    private final DataSource dataSource;
    private final MeterRegistry meterRegistry;
    private final HealthCheckRegistry healthCheckRegistry;
    private @Nullable Scheduler scheduler;

    public TaskSchedulerInitializer(HealthCheckRegistry healthCheckRegistry) {
        this(ConfigProvider.getConfig(), DataSourceRegistry.getInstance().getDefault(),
                Metrics.globalRegistry, healthCheckRegistry);
    }

    TaskSchedulerInitializer(
            Config config,
            DataSource dataSource,
            MeterRegistry meterRegistry,
            HealthCheckRegistry healthCheckRegistry) {
        this.config = config;
        this.dataSource = dataSource;
        this.meterRegistry = meterRegistry;
        this.healthCheckRegistry = healthCheckRegistry;
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        if (!config.getOptionalValue(ConfigKeys.TASK_SCHEDULER_ENABLED, boolean.class).orElse(true)) {
            LOGGER.info("Not starting task scheduler because it is disabled");
            return;
        }

        final var dexEngine = (DexEngine) event.getServletContext().getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        final var pluginManager = (PluginManager) event.getServletContext().getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        final var secretManager = (SecretManager) event.getServletContext().getAttribute(SecretManager.class.getName());
        requireNonNull(secretManager, "secretManager has not been initialized");

        final List<RecurringTask<Void>> tasks = recurringTasks(config, dexEngine, pluginManager, secretManager);

        LOGGER.info("Starting task scheduler");
        final int threads = config.getValue(ConfigKeys.TASK_SCHEDULER_THREADS, int.class);
        final var pollInterval = Duration.ofMillis(
                config.getValue(ConfigKeys.TASK_SCHEDULER_POLL_INTERVAL_MS, long.class));
        final var shutdownMaxWait = Duration.ofMillis(
                config.getValue(ConfigKeys.TASK_SCHEDULER_SHUTDOWN_MAX_WAIT_MS, long.class));
        scheduler = Scheduler
                .create(dataSource)
                .startTasks(tasks)
                .threads(threads)
                .pollingInterval(pollInterval)
                .pollUsingLockAndFetch(0.5, 1.0)
                .shutdownMaxWait(shutdownMaxWait)
                .addSchedulerListener(new StatsRegistryAdapter(new MicrometerStatsRegistry(meterRegistry, tasks)))
                .addSchedulerListener(new AbstractSchedulerListener() {

                    @Override
                    public void onExecutionStart(CurrentlyExecuting event) {
                        LOGGER.debug("Executing task '{}'", event.getExecution().getTaskName());
                    }

                    @Override
                    public void onExecutionComplete(ExecutionComplete event) {
                        switch (event.getResult()) {
                            case OK -> LOGGER.debug(
                                    "Task '{}' completed successfully in {}",
                                    event.getExecution().getTaskName(),
                                    event.getDuration());
                            case FAILED -> LOGGER.warn(
                                    "Task '{}' failed in {}",
                                    event.getExecution().getTaskName(),
                                    event.getDuration(),
                                    event.getCause().orElse(null));
                        }
                    }

                })
                .build();
        scheduler.start();

        healthCheckRegistry.addCheck(new TaskSchedulerHealthCheck(scheduler));
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (scheduler != null) {
            LOGGER.info("Stopping task scheduler");
            scheduler.stop();
        }
    }

    static List<RecurringTask<Void>> recurringTasks(
            Config config,
            DexEngine dexEngine,
            PluginManager pluginManager,
            SecretManager secretManager) {
        final var vulnDataSourceMirrorService = new VulnDataSourceMirrorService(pluginManager, dexEngine);

        return List.of(
                recurringTask(
                        "Package Metadata Maintenance",
                        getCronScheduleForTask(PackageMetadataMaintenanceTask.class),
                        new PackageMetadataMaintenanceTask()),
                recurringTask(
                        "Defect Dojo Upload",
                        getCronScheduleForTask(DefectDojoUploadTask.class),
                        new DefectDojoUploadTask(HttpClient.INSTANCE, secretManager)),
                recurringTaskTriggeredOnFirstRun(
                        "EPSS Mirror",
                        getCronScheduleForTask(EpssMirrorTask.class),
                        new EpssMirrorTask(HttpClient.INSTANCE)),
                recurringTask(
                        "Fortify SSC Upload",
                        getCronScheduleForTask(FortifySscUploadTask.class),
                        new FortifySscUploadTask(HttpClient.INSTANCE, secretManager)),
                recurringTaskTriggeredOnFirstRun(
                        "GitHub Advisories Mirror",
                        getCronScheduleFromConfig(config, "dt.task.git.hub.advisory.mirror.cron"),
                        () -> vulnDataSourceMirrorService.trigger("github", null)),
                recurringTask(
                        "Kenna Security Upload",
                        getCronScheduleForTask(KennaSecurityUploadTask.class),
                        new KennaSecurityUploadTask(HttpClient.INSTANCE, secretManager)),
                recurringTask(
                        "Metrics Maintenance",
                        getCronScheduleForTask(MetricsMaintenanceTask.class),
                        new MetricsMaintenanceTask()),
                recurringTaskTriggeredOnFirstRun(
                        "NVD Mirror",
                        getCronScheduleFromConfig(config, "dt.task.nist.mirror.cron"),
                        () -> vulnDataSourceMirrorService.trigger("nvd", null)),
                recurringTaskTriggeredOnFirstRun(
                        "OSV Mirror",
                        getCronScheduleFromConfig(config, "dt.task.osv.mirror.cron"),
                        () -> vulnDataSourceMirrorService.trigger("osv", null)),
                recurringTask(
                        "Package Metadata Resolution",
                        getCronScheduleFromConfig(config, "dt.task.package-metadata-resolution.cron"),
                        () -> dexEngine.createRun(
                                new CreateWorkflowRunRequest<>(ResolvePackageMetadataWorkflow.class)
                                        .withWorkflowInstanceId(ResolvePackageMetadataWorkflow.INSTANCE_ID))),
                recurringTask(
                        "Portfolio Metrics Update",
                        getCronScheduleFromConfig(config, "dt.task.portfolio-metrics-update.cron"),
                        () -> dexEngine.createRun(
                                new CreateWorkflowRunRequest<>(UpdatePortfolioMetricsWorkflow.class)
                                        .withWorkflowInstanceId(UpdatePortfolioMetricsWorkflow.INSTANCE_ID))),
                recurringTask(
                        "Portfolio Vulnerability Analysis",
                        getCronScheduleForTask(VulnerabilityAnalysisTask.class),
                        new VulnerabilityAnalysisTask(dexEngine)),
                recurringTask(
                        "Project Maintenance",
                        getCronScheduleForTask(ProjectMaintenanceTask.class),
                        new ProjectMaintenanceTask()),
                recurringTask(
                        "Tag Maintenance",
                        getCronScheduleForTask(TagMaintenanceTask.class),
                        new TagMaintenanceTask()),
                recurringTask(
                        "Vulnerability Database Maintenance",
                        getCronScheduleForTask(VulnerabilityDatabaseMaintenanceTask.class),
                        new VulnerabilityDatabaseMaintenanceTask()),
                recurringTask(
                        "Vulnerability Metrics Update",
                        getCronScheduleForTask(VulnerabilityMetricsUpdateTask.class),
                        new VulnerabilityMetricsUpdateTask()),
                recurringTaskTriggeredOnFirstRun(
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
                        }),
                recurringTask(
                        "Expired Session Cleanup",
                        getCronScheduleFromConfig(config, "dt.task.expired-session-cleanup.cron"),
                        () -> new SessionTokenService().deleteExpiredSessions()),
                recurringTask(
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
                        }),
                recurringTaskTriggeredOnFirstRun(
                        "Telemetry Submission",
                        getCronScheduleFromConfig(config, "dt.task.telemetry-submission.cron"),
                        new TelemetrySubmissionTask(HttpClient.INSTANCE, config)));
    }

    private static RecurringTask<Void> recurringTask(String name, Schedule schedule, Runnable runnable) {
        return Tasks.recurring(name, schedule).execute((_, _) -> runnable.run());
    }

    private static RecurringTask<Void> recurringTaskTriggeredOnFirstRun(String name, Schedule schedule, Runnable runnable) {
        return recurringTask(name, new TriggerOnFirstRunSchedule(schedule), runnable);
    }

    record TriggerOnFirstRunSchedule(Schedule delegate) implements Schedule {

        private static final Duration MAX_STARTUP_DELAY = Duration.ofMinutes(1);

        @Override
        public Instant getNextExecutionTime(ExecutionComplete executionComplete) {
            return delegate.getNextExecutionTime(executionComplete);
        }

        @Override
        public Instant getInitialExecutionTime(Instant now) {
            final long delayMillis = ThreadLocalRandom.current().nextLong(MAX_STARTUP_DELAY.toMillis());
            return now.plusMillis(delayMillis);
        }

        @Override
        public boolean isDeterministic() {
            return false;
        }

        @Override
        public boolean isDisabled() {
            return delegate.isDisabled();
        }

    }

    @Nullable
    Scheduler scheduler() {
        return scheduler;
    }

}
