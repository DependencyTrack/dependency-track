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

    public static final String DEV_SERVICES_ENABLED = "dt.dev.services.enabled";
    public static final String DEV_SERVICES_IMAGE_FRONTEND = "dt.dev.services.image.frontend";
    public static final String DEV_SERVICES_IMAGE_POSTGRES = "dt.dev.services.image.postgres";
    public static final String DEV_SERVICES_PORT_FRONTEND = "dt.dev.services.port.frontend";

    public static final String INIT_TASKS_ENABLED = "dt.init.tasks.enabled";
    public static final String INIT_TASKS_DATASOURCE_NAME = "dt.init.tasks.datasource.name";
    public static final String INIT_TASKS_DATASOURCE_CLOSE_AFTER_USE = "dt.init.tasks.datasource.close-after-use";
    public static final String INIT_AND_EXIT = "dt.init.and.exit";

    public static final String MANAGEMENT_HOST = "dt.management.host";
    public static final String MANAGEMENT_PORT = "dt.management.port";

    public static final String METRICS_ENABLED = "dt.metrics.enabled";
    public static final String METRICS_AUTH_USERNAME = "dt.metrics.auth.username";
    public static final String METRICS_AUTH_PASSWORD = "dt.metrics.auth.password";

    public static final String TASK_SCHEDULER_ENABLED = "dt.task-scheduler.enabled";
    public static final String TASK_SCHEDULER_THREADS = "dt.task-scheduler.threads";
    public static final String TASK_SCHEDULER_POLL_INTERVAL_MS = "dt.task-scheduler.poll-interval-ms";
    public static final String TASK_SCHEDULER_SHUTDOWN_MAX_WAIT_MS = "dt.task-scheduler.shutdown-max-wait-ms";

    public static final String VULNERABILITY_POLICY_BUNDLE_URL = "dt.vulnerability.policy.bundle.url";
    public static final String VULNERABILITY_POLICY_BUNDLE_AUTH_USERNAME = "dt.vulnerability.policy.bundle.auth.username";
    public static final String VULNERABILITY_POLICY_BUNDLE_AUTH_PASSWORD = "dt.vulnerability.policy.bundle.auth.password";
    public static final String VULNERABILITY_POLICY_BUNDLE_AUTH_BEARER_TOKEN = "dt.vulnerability.policy.bundle.auth.bearer.token";

    public static final String CACHE_PROVIDER = "dt.cache.provider";
    public static final String FILE_STORAGE_PROVIDER = "dt.file-storage.provider";
    public static final String SECRET_MANAGEMENT_PROVIDER = "dt.secret-management.provider";

    public static final String NOTIFICATION_OUTBOX_RELAY_ENABLED = "dt.notification.outbox-relay.enabled";
    public static final String NOTIFICATION_OUTBOX_RELAY_POLL_INTERVAL_MS = "dt.notification.outbox-relay.poll-interval-ms";
    public static final String NOTIFICATION_OUTBOX_RELAY_BATCH_SIZE = "dt.notification.outbox-relay.batch-size";
    public static final String NOTIFICATION_OUTBOX_RELAY_LARGE_NOTIFICATION_THRESHOLD_BYTES = "dt.notification.outbox-relay.large-notification-threshold-bytes";

    public static final String TELEMETRY_SUBMISSION_ENABLED_DEFAULT = "dt.telemetry.submission.enabled.default";

    private ConfigKeys() {
    }

}
