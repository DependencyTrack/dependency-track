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
package org.dependencytrack.notification.publishing.webhook;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.publishing.http.HttpNotificationResponses.ensureSuccessful2xxResponse;

/**
 * @since 5.0.0
 */
final class WebhookNotificationPublisher implements NotificationPublisher {

    private final HttpClient httpClient;

    WebhookNotificationPublisher(HttpClient httpClient) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final var ruleConfig = ctx.ruleConfig(WebhookNotificationPublisherRuleConfigV1.class);

        final String mimeType;
        final BodyPublisher body;
        if (Boolean.TRUE.equals(ruleConfig.getPublishProtobuf())) {
            // https://protobuf.dev/reference/protobuf/mime-types/
            mimeType = "application/protobuf";
            body = BodyPublishers.ofByteArray(notification.toByteArray());
        } else {
            final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);
            if (renderedTemplate == null) {
                throw new IllegalStateException("No template configured");
            }

            mimeType = renderedTemplate.mimeType();
            body = BodyPublishers.ofString(renderedTemplate.content());
        }

        final var requestBuilder = HttpRequest
                .newBuilder(ruleConfig.getDestinationUrl())
                .header("Content-Type", mimeType)
                .POST(body)
                .timeout(Duration.ofSeconds(10));

        final String authHeaderName = ruleConfig.getAuthHeaderName();
        final String authHeaderValue = ruleConfig.getAuthHeaderValue();
        if (authHeaderName != null && authHeaderValue != null) {
            requestBuilder.header(authHeaderName, authHeaderValue);
        }

        try {
            final HttpResponse<String> response = httpClient.send(requestBuilder.build(), BodyHandlers.ofString());
            ensureSuccessful2xxResponse(response);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        } catch (IOException e) {
            RetryablePublishException.throwIfRetryableNetworkError(e, "Request failed while sending notification");
            throw e;
        }
    }

}
