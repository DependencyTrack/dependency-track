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
package org.dependencytrack.notification.publishing.http;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public abstract class AbstractHttpNotificationPublisher implements NotificationPublisher {

    private final HttpClient httpClient;

    protected AbstractHttpNotificationPublisher(HttpClient httpClient) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final var ruleConfig = ctx.ruleConfig(HttpNotificationPublisherRuleConfigV1.class);

        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        final var request = HttpRequest
                .newBuilder(ruleConfig.getDestinationUrl())
                .header("Content-Type", renderedTemplate.mimeType())
                .POST(BodyPublishers.ofString(renderedTemplate.content()))
                .timeout(Duration.ofSeconds(10))
                .build();

        try {
            final var response = httpClient.send(request, BodyHandlers.discarding());
            RetryablePublishException.throwIfRetryableError(response);
            final int statusCode = response.statusCode();
            if (statusCode < 200 || statusCode > 299) {
                throw new IllegalStateException("Request failed with unexpected response code: " + statusCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        } catch (HttpTimeoutException e) {
            throw new RetryablePublishException("Timed out while sending request", e);
        }
    }

}
