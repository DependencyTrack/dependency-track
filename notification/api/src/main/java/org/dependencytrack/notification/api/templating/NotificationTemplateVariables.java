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
package org.dependencytrack.notification.api.templating;

/**
 * Names of variables available in the notification template context.
 * <p>
 * Consumers that supply or reference template context values should use these
 * constants rather than a concrete template-engine implementation.
 *
 * @since 5.0.0
 */
public final class NotificationTemplateVariables {

    /**
     * Application base URL used to construct frontend links.
     */
    public static final String BASE_URL = "baseUrl";

    /**
     * Notification timestamp as epoch seconds.
     */
    public static final String TIMESTAMP_EPOCH_SECONDS = "timestampEpochSeconds";

    /**
     * Notification timestamp as a formatted string.
     */
    public static final String TIMESTAMP = "timestamp";

    /**
     * The notification protobuf message.
     */
    public static final String NOTIFICATION = "notification";

    /**
     * Unpacked notification subject (when present).
     */
    public static final String SUBJECT = "subject";

    /**
     * Notification subject serialized as JSON (when present).
     */
    public static final String SUBJECT_JSON = "subjectJson";

    private NotificationTemplateVariables() {}
}
