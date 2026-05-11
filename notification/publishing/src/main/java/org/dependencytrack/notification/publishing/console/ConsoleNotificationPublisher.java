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
package org.dependencytrack.notification.publishing.console;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @since 5.0.0
 */
final class ConsoleNotificationPublisher implements NotificationPublisher {

    private final OutputStream outputStream;

    ConsoleNotificationPublisher(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        outputStream.write(renderedTemplate.content().getBytes());
    }

}
