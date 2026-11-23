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

import com.google.protobuf.Any;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.api.templating.NotificationTemplateVariables;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.publishing.email.EmailNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.mattermost.MattermostNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.msteams.MsTeamsNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.slack.SlackNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.webex.WebexNotificationPublisherFactory;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for https://github.com/DependencyTrack/dependency-track/issues/3723:
 * the default notification templates must render a vulnerability's aliases
 * (e.g. the OSV alias of the test vulnerability) whenever they render the
 * vulnerability itself.
 */
class DefaultTemplateAliasesTest {

    private static final List<NotificationPublisherFactory> VULNERABILITY_TEMPLATE_FACTORIES = List.of(
            new EmailNotificationPublisherFactory(),
            new SlackNotificationPublisherFactory(),
            new MsTeamsNotificationPublisherFactory(),
            new MattermostNotificationPublisherFactory(),
            new WebexNotificationPublisherFactory(),
            new JiraNotificationPublisherFactory());

    private static Stream<NotificationPublisherFactory> factories() {
        return VULNERABILITY_TEMPLATE_FACTORIES.stream();
    }

    private static final Map<String, Object> ADDITIONAL_CONTEXT = Map.of(
            // referenced by the JIRA default template
            "jiraProjectKey", "EXAMPLE",
            "jiraTicketType", "TASK");

    private static NotificationTemplateRenderer rendererFor(NotificationPublisherFactory factory) {
        // strictVariables enabled so rendering fails when default templates
        // reference nonexistent variables.
        return new PebbleNotificationTemplateRendererFactory(
                        Map.of(NotificationTemplateVariables.BASE_URL, () -> "https://example.com"),
                        /* strictVariables */ true)
                .createRenderer(factory.defaultTemplate());
    }

    @ParameterizedTest
    @MethodSource("factories")
    void newVulnerabilityTemplateRendersAliases(NotificationPublisherFactory factory) {
        final Notification notification = TestNotificationFactory.createNewVulnerabilityTestNotification();

        final String content = rendererFor(factory).render(notification, ADDITIONAL_CONTEXT).content();

        assertThat(content)
                .as("alias vulnId missing from %s", factory.getClass().getSimpleName())
                .contains("OSV-001");
        assertThat(content)
                .as("alias source missing from %s", factory.getClass().getSimpleName())
                .contains("OSV");
    }

    @ParameterizedTest
    @MethodSource("factories")
    void newVulnerabilityTemplateOmitsAliasSectionWhenNoAliases(NotificationPublisherFactory factory)
            throws Exception {
        final Notification withAliases = TestNotificationFactory.createNewVulnerabilityTestNotification();
        final NewVulnerabilitySubject subject =
                NewVulnerabilitySubject.parseFrom(withAliases.getSubject().getValue());
        final Vulnerability vulnerabilityWithoutAliases = subject.getVulnerability().toBuilder()
                .clearAliases()
                .build();
        final Notification notification = withAliases.toBuilder()
                .setSubject(Any.pack(subject.toBuilder()
                        .setVulnerability(vulnerabilityWithoutAliases)
                        .build()))
                .build();

        final String content = rendererFor(factory).render(notification, ADDITIONAL_CONTEXT).content();

        assertThat(content).doesNotContain("Aliases");
    }

    @Test
    void newVulnerableDependencyTemplateRendersAliases() {
        // The email and JIRA default templates list the vulnerabilities of a
        // newly vulnerable dependency; each entry must carry its aliases.
        final Notification notification = TestNotificationFactory.createNewVulnerableDependencyTestNotification();
        for (final NotificationPublisherFactory factory :
                List.of(new EmailNotificationPublisherFactory(), new JiraNotificationPublisherFactory())) {
            final String content = rendererFor(factory).render(notification, ADDITIONAL_CONTEXT).content();
            assertThat(content)
                    .as("alias missing from %s", factory.getClass().getSimpleName())
                    .contains("OSV-001 (OSV)");
        }
    }

    @Test
    void emailSummaryTemplateRendersFindingAliases() {
        final Notification notification =
                TestNotificationFactory.createNewVulnerabilitiesSummaryTestNotification();

        final String content = rendererFor(new EmailNotificationPublisherFactory())
                .render(notification)
                .content();

        assertThat(content).contains("Vulnerability Aliases: OSV-001 (OSV)");
    }
}
