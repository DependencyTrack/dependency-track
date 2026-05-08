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
package org.dependencytrack.notification.api.publishing;

import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;

import java.io.IOException;

/**
 * @since 5.0.0
 */
@ExtensionPointSpec(name = "notification-publisher", required = false)
public interface NotificationPublisher extends ExtensionPoint {

    /**
     * Publish a given notification.
     *
     * @param ctx          Context in which the publishing is executed.
     * @param notification The notification to publish.
     * @throws IOException               When publishing failed.
     * @throws RetryablePublishException When publishing failed with a retryable cause.
     */
    void publish(NotificationPublishContext ctx, Notification notification) throws IOException;

}
