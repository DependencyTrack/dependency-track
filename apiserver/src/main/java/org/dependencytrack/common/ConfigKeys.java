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
package org.dependencytrack.common;

/**
 * @since 5.0.0
 */
public final class ConfigKeys {

    public static final String DEV_SERVICES_ENABLED = "dt.dev-services.enabled";
    public static final String DEV_SERVICES_CONTAINER_REUSE_ENABLED = "dt.dev-services.container-reuse.enabled";
    public static final String DEV_SERVICES_FRONTEND_IMAGE = "dt.dev-services.frontend-image";
    public static final String DEV_SERVICES_POSTGRES_IMAGE = "dt.dev-services.postgres-image";
    public static final String DEV_SERVICES_FRONTEND_PORT = "dt.dev-services.frontend-port";

    public static final String INIT_TASKS_ENABLED = "dt.init-tasks.enabled";
    public static final String INIT_TASKS_DATASOURCE_NAME = "dt.init-tasks.datasource.name";
    public static final String INIT_TASKS_DATASOURCE_CLOSE_AFTER_COMPLETION = "dt.init-tasks.datasource.close-after-completion";
    public static final String INIT_TASKS_EXIT_AFTER_COMPLETION = "dt.init-tasks.exit-after-completion";

    public static final String MANAGEMENT_HOST = "dt.management.host";
    public static final String MANAGEMENT_PORT = "dt.management.port";

    public static final String METRICS_ENABLED = "dt.metrics.enabled";
    public static final String METRICS_AUTH_USERNAME = "dt.metrics.auth.username";
    public static final String METRICS_AUTH_PASSWORD = "dt.metrics.auth.password";

    public static final String TASK_SCHEDULER_ENABLED = "dt.task-scheduler.enabled";
    public static final String TASK_SCHEDULER_THREADS = "dt.task-scheduler.threads";
    public static final String TASK_SCHEDULER_POLL_INTERVAL_MS = "dt.task-scheduler.poll-interval-ms";
    public static final String TASK_SCHEDULER_SHUTDOWN_MAX_WAIT_MS = "dt.task-scheduler.shutdown-max-wait-ms";

    public static final String TASK_PACKAGE_METADATA_MAINTENANCE_CRON = "dt.task.package-metadata-maintenance.cron";
    public static final String TASK_PACKAGE_METADATA_RESOLUTION_CRON = "dt.task.package-metadata-resolution.cron";
    public static final String TASK_DEFECT_DOJO_UPLOAD_CRON = "dt.task.defect-dojo-upload.cron";
    public static final String TASK_EPSS_MIRROR_CRON = "dt.task.epss-mirror.cron";
    public static final String TASK_KEV_MIRROR_CRON = "dt.task.kev-mirror.cron";
    public static final String TASK_FORTIFY_SSC_UPLOAD_CRON = "dt.task.fortify-ssc-upload.cron";
    public static final String TASK_GITHUB_ADVISORY_VULN_DATA_SOURCE_MIRROR_CRON = "dt.task.github-advisory-vuln-data-source-mirror.cron";
    public static final String TASK_KENNA_SECURITY_UPLOAD_CRON = "dt.task.kenna-security-upload.cron";
    public static final String TASK_METRICS_MAINTENANCE_CRON = "dt.task.metrics-maintenance.cron";
    public static final String TASK_NVD_VULN_DATA_SOURCE_MIRROR_CRON = "dt.task.nvd-vuln-data-source-mirror.cron";
    public static final String TASK_OSV_VULN_DATA_SOURCE_MIRROR_CRON = "dt.task.osv-vuln-data-source-mirror.cron";
    public static final String TASK_PORTFOLIO_ANALYSIS_CRON = "dt.task.portfolio-analysis.cron";
    public static final String TASK_PORTFOLIO_METRICS_UPDATE_CRON = "dt.task.portfolio-metrics-update.cron";
    public static final String TASK_PROJECT_MAINTENANCE_CRON = "dt.task.project-maintenance.cron";
    public static final String TASK_TAG_MAINTENANCE_CRON = "dt.task.tag-maintenance.cron";
    public static final String TASK_VULN_DATABASE_MAINTENANCE_CRON = "dt.task.vuln-database-maintenance.cron";
    public static final String TASK_VULN_METRICS_UPDATE_CRON = "dt.task.vuln-metrics-update.cron";
    public static final String TASK_VULN_POLICY_BUNDLE_SYNC_CRON = "dt.task.vuln-policy-bundle-sync.cron";
    public static final String TASK_EXPIRED_SESSION_CLEANUP_CRON = "dt.task.expired-session-cleanup.cron";
    public static final String TASK_SCHEDULED_NOTIFICATION_DISPATCH_CRON = "dt.task.scheduled-notification-dispatch.cron";
    public static final String TASK_TELEMETRY_SUBMISSION_CRON = "dt.task.telemetry-submission.cron";

    public static final String VULN_POLICY_BUNDLE_URL = "dt.vuln-policy-bundle.url";
    public static final String VULN_POLICY_BUNDLE_AUTH_USERNAME = "dt.vuln-policy-bundle.auth.username";
    public static final String VULN_POLICY_BUNDLE_AUTH_PASSWORD = "dt.vuln-policy-bundle.auth.password";
    public static final String VULN_POLICY_BUNDLE_AUTH_BEARER_TOKEN = "dt.vuln-policy-bundle.auth.bearer-token";

    public static final String CACHE_PROVIDER = "dt.cache.provider";
    public static final String FILE_STORAGE_PROVIDER = "dt.file-storage.provider";
    public static final String SECRET_MANAGEMENT_PROVIDER = "dt.secret-management.provider";

    public static final String NOTIFICATION_OUTBOX_RELAY_ENABLED = "dt.notification.outbox-relay.enabled";
    public static final String NOTIFICATION_OUTBOX_RELAY_POLL_INTERVAL_MS = "dt.notification.outbox-relay.poll-interval-ms";
    public static final String NOTIFICATION_OUTBOX_RELAY_BATCH_SIZE = "dt.notification.outbox-relay.batch-size";
    public static final String NOTIFICATION_OUTBOX_RELAY_LARGE_NOTIFICATION_THRESHOLD_BYTES = "dt.notification.outbox-relay.large-notification-threshold-bytes";

    public static final String TELEMETRY_SUBMISSION_DEFAULT_ENABLED = "dt.telemetry.submission.default-enabled";

    private ConfigKeys() {
    }

}
