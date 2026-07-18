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
package org.dependencytrack.notification.publishing.jira;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * @since 5.0.0
 */
final class JiraNotificationPublisher implements NotificationPublisher {

    private final JiraNotificationPublisherGlobalConfigV1 globalConfig;
    private final HttpClient httpClient;

    JiraNotificationPublisher(
            JiraNotificationPublisherGlobalConfigV1 globalConfig,
            HttpClient httpClient) {
        this.globalConfig = globalConfig;
        this.httpClient = httpClient;
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final var ruleConfig = ctx.ruleConfig(JiraNotificationPublisherRuleConfigV1.class);

        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(
                notification,
                Map.ofEntries(
                        Map.entry("jiraProjectKey", ruleConfig.getProjectKey()),
                        Map.entry("jiraTicketType", ruleConfig.getIssueType())));
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        final String authHeader;
        if (globalConfig.getUsername() != null) {
            final var credentials = Base64.getEncoder().encodeToString(
                    "%s:%s".formatted(globalConfig.getUsername(), globalConfig.getPasswordOrToken()).getBytes());
            authHeader = "Basic " + credentials;
        } else {
            authHeader = "Bearer " + globalConfig.getPasswordOrToken();
        }

        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/rest/api/2/issue".formatted(globalConfig.getApiUrl())))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(renderedTemplate.content()))
                .timeout(Duration.ofSeconds(10))
                .build();

        final HttpResponse<?> response;
        try {
            response = httpClient.send(request, BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        } catch (IOException e) {
            RetryablePublishException.throwIfRetryableNetworkError(e, "Request failed while sending notification");
            throw e;
        }

        if (response.statusCode() != 201) {
            throw new IllegalStateException(
                    "Request failed with retryable response code: " + response.statusCode());
        }
    }

}
