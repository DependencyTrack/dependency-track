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
package org.dependencytrack.notification.publishing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.Any;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplateVariables;
import org.dependencytrack.notification.proto.v1.PolicyViolationUpdatedSubject;
import org.dependencytrack.notification.publishing.console.ConsoleNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.email.EmailNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.mattermost.MattermostNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.msteams.MsTeamsNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.slack.SlackNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.webex.WebexNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.webhook.WebhookNotificationPublisherFactory;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyViolationUpdatedTemplateTest {

    private static Stream<NotificationPublisherFactory> publisherFactories() {
        return Stream.of(
                new ConsoleNotificationPublisherFactory(),
                new EmailNotificationPublisherFactory(),
                new JiraNotificationPublisherFactory(),
                new MattermostNotificationPublisherFactory(),
                new MsTeamsNotificationPublisherFactory(),
                new SlackNotificationPublisherFactory(),
                new WebexNotificationPublisherFactory(),
                new WebhookNotificationPublisherFactory());
    }

    @ParameterizedTest
    @MethodSource("publisherFactories")
    void shouldRenderOldAndNewMessagesAndEscapeJson(NotificationPublisherFactory factory) throws Exception {
        final var notification = TestNotificationFactory.createPolicyViolationUpdatedTestNotification();
        final var subject = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .setPreviousMessage("CVE-A \"quoted\"\nline\t\\")
                .setCurrentMessage("CVE-B \"quoted\"\nline\t\\")
                .build();
        final var renderer = new PebbleNotificationTemplateRendererFactory(
                        Map.of(NotificationTemplateVariables.BASE_URL, () -> "https://example.com"), true)
                .createRenderer(factory.defaultTemplate());
        final var rendered = renderer.render(
                notification.toBuilder().setSubject(Any.pack(subject)).build(),
                Map.of("jiraProjectKey", "TEST", "jiraTicketType", "Task"));

        assertThat(rendered).isNotNull();
        assertThat(rendered.content())
                .contains("CVE-A", "CVE-B", subject.getPolicyViolation().getUuid(), "2006-06-06T06:06:06");
        if (rendered.mimeType().equals("application/json")) {
            assertThat(new ObjectMapper().readTree(rendered.content()).isObject())
                    .isTrue();
        }
    }

    @Test
    void webhookShouldPreserveNullPresenceAndExactMessages() throws Exception {
        final var notification = TestNotificationFactory.createPolicyViolationUpdatedTestNotification();
        final var subject = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .clearCurrentMessage()
                .setPreviousMessage("CVE-A \"quoted\"\nline")
                .build();
        final var renderer = new PebbleNotificationTemplateRendererFactory(Map.of(), true)
                .createRenderer(new WebhookNotificationPublisherFactory().defaultTemplate());
        final var rendered = renderer.render(
                notification.toBuilder().setSubject(Any.pack(subject)).build());
        assertThat(rendered).isNotNull();
        final var jsonSubject = new ObjectMapper()
                .readTree(rendered.content())
                .path("notification")
                .path("subject");
        assertThat(jsonSubject.path("previousMessage").asText()).isEqualTo(subject.getPreviousMessage());
        assertThat(jsonSubject.has("currentMessage")).isFalse();
        assertThat(jsonSubject.path("changedAt").asText()).isEqualTo("2006-06-06T06:06:06.666Z");
    }

    private static Stream<Arguments> reviewedContexts() {
        return publisherFactories()
                .flatMap(factory -> Stream.of(
                        Arguments.of(factory, null), Arguments.of(factory, false), Arguments.of(factory, true)));
    }

    @ParameterizedTest
    @MethodSource("reviewedContexts")
    void shouldRenderReviewedContextAndPreserveUnknownSuppression(
            NotificationPublisherFactory factory, @Nullable Boolean suppressed) throws Exception {
        final var notification = TestNotificationFactory.createReviewedPolicyViolationUpdatedTestNotification();
        final var subjectBuilder = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .clearSuppressed();
        if (suppressed != null) {
            subjectBuilder.setSuppressed(suppressed);
        }
        final var subject = subjectBuilder.build();
        final var renderer = new PebbleNotificationTemplateRendererFactory(
                        Map.of(NotificationTemplateVariables.BASE_URL, () -> "https://example.com"), true)
                .createRenderer(factory.defaultTemplate());
        final var rendered = renderer.render(
                notification.toBuilder().setSubject(Any.pack(subject)).build(),
                Map.of("jiraProjectKey", "TEST", "jiraTicketType", "Task"));
        assertThat(rendered).isNotNull();
        assertThat(rendered.content())
                .contains(
                        "APPROVED",
                        subject.getPolicyViolation().getUuid(),
                        subject.getPreviousMessage(),
                        subject.getCurrentMessage());
        assertThat(rendered.content()).containsIgnoringCase("review");
        if (rendered.mimeType().equals("application/json")) {
            assertThat(new ObjectMapper().readTree(rendered.content()).isObject())
                    .isTrue();
        }
        if (factory instanceof WebhookNotificationPublisherFactory) {
            final var jsonSubject = new ObjectMapper()
                    .readTree(rendered.content())
                    .path("notification")
                    .path("subject");
            assertThat(jsonSubject.path("analysisState").asText()).isEqualTo("APPROVED");
            assertThat(jsonSubject.has("suppressed")).isEqualTo(suppressed != null);
            if (suppressed != null) {
                assertThat(jsonSubject.path("suppressed").asBoolean()).isEqualTo(suppressed);
            }
        } else if (suppressed == null) {
            assertThat(rendered.content()).contains("not recorded");
        } else {
            assertThat(rendered.content()).contains(suppressed.toString());
        }
    }
}
