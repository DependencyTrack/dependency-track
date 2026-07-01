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
package org.dependencytrack.notification.publishing.email;

import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.mail.Address;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.icegreen.greenmail.configuration.GreenMailConfiguration.aConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomConsumedTestNotification;

class EmailNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final GreenMailExtension GREEN_MAIL =
            new GreenMailExtension(ServerSetup.SMTP.dynamicPort())
                    .withConfiguration(aConfig().withUser("username", "password"));

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new EmailNotificationPublisherFactory();
    }

    @Override
    protected void customizeDeploymentConfig(Map<String, String> deploymentConfig) {
        deploymentConfig.put("allow-local-connections", "true");
    }

    @Override
    protected void customizeGlobalConfig(RuntimeConfig globalConfig) {
        final var emailGlobalConfig = (EmailNotificationPublisherGlobalConfigV1) globalConfig;
        emailGlobalConfig.setEnabled(true);
        emailGlobalConfig.setHost(GREEN_MAIL.getSmtp().getBindTo());
        emailGlobalConfig.setPort(GREEN_MAIL.getSmtp().getPort());
        emailGlobalConfig.setUsername("username");
        emailGlobalConfig.setPassword("password");
        emailGlobalConfig.setSenderAddress("dependencytrack@example.com");
    }

    @Override
    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
        final var emailRuleConfig = (EmailNotificationPublisherRuleConfigV1) ruleConfig;
        emailRuleConfig.setRecipientAddresses(Set.of("username@example.com"));
    }

    @Override
    protected void validateNotificationPublish(Notification notification) {
        switch (notification.getGroup()) {
            case GROUP_BOM_CONSUMED -> validateBomConsumedNotificationPublish();
            case GROUP_BOM_PROCESSING_FAILED -> validateBomProcessingFailedNotificationPublish();
            case GROUP_BOM_VALIDATION_FAILED -> validateBomValidationFailedNotificationPublish();
            case GROUP_NEW_VULNERABILITY -> validateNewVulnerabilityNotificationPublish();
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> validateNewVulnerableDependencyNotificationPublish();
            case GROUP_NEW_VULNERABILITIES_SUMMARY -> validateNewVulnerabilitiesSummaryNotificationPublish();
            case GROUP_NEW_POLICY_VIOLATIONS_SUMMARY -> validateNewPolicyViolationsSummaryNotificationPublish();
        }
    }

    private void validateBomConsumedNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Consumed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Consumed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                A CycloneDX BOM was consumed and will be processed
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateBomProcessingFailedNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Processing Failed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Processing Failed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                Cause:
                cause
                
                --------------------------------------------------------------------------------
                
                An error occurred while processing a BOM
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateBomValidationFailedNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Validation Failed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Validation Failed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                Errors:
                
                cause 1
                
                cause 2
                
                
                --------------------------------------------------------------------------------
                
                An error occurred while validating a BOM
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateNewVulnerabilityNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] New Vulnerability Identified on Project: [projectName : projectVersion]");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                New Vulnerability Identified on Project: [projectName : projectVersion]
                
                --------------------------------------------------------------------------------
                
                Vulnerability ID:  INT-001
                Vulnerability URL: https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001
                Severity:          MEDIUM
                Source:            INTERNAL
                Component:         componentName : componentVersion
                Component URL:     https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                --------------------------------------------------------------------------------
                
                Other affected projects: https://example.com/vulnerabilities/INTERNAL/INT-001/affectedProjects
                
                --------------------------------------------------------------------------------
                
                vulnerabilityDescription
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateNewVulnerableDependencyNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Vulnerable Dependency Introduced on Project: [projectName : projectVersion]");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Vulnerable Dependency Introduced on Project: [projectName : projectVersion]
                
                --------------------------------------------------------------------------------
                
                Project:           projectName : projectVersion
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                Component:         componentName : componentVersion
                Component URL:     https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                
                Vulnerabilities
                
                Vulnerability ID:  INT-001
                Vulnerability URL: https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001
                Severity:          MEDIUM
                Source:            INTERNAL
                Description:
                vulnerabilityDescription
                
                
                
                --------------------------------------------------------------------------------
                
                A dependency was introduced that contains 1 known vulnerability
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateNewVulnerabilitiesSummaryNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] New Vulnerabilities Summary");
        assertThat(message.content()).isEqualToIgnoringWhitespace("""
                New Vulnerabilities Summary
                
                --------------------------------------------------------------------------------
                
                Overview:
                - New Vulnerabilities: 1 (Suppressed: 1)
                - Affected Projects:   1
                - Affected Components: 1
                - Since:               1970-01-01T00:01:06Z
                
                --------------------------------------------------------------------------------
                
                Project Summaries:
                
                - Project: [projectName : projectVersion]
                  Project URL: https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                  + New Vulnerabilities Of Severity MEDIUM: 1 (Suppressed: 1)
                
                --------------------------------------------------------------------------------
                
                Vulnerability Details:
                
                - Project: [projectName : projectVersion]
                  Project URL: https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                  + Vulnerability ID:       INT-001
                    Vulnerability Source:   INTERNAL
                    Vulnerability Severity: MEDIUM
                    Vulnerability URL:      https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001
                    Component:              componentName : componentVersion
                    Component URL:          https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                    Timestamp:              1970-01-01T18:31:06Z
                    Analysis State:         FALSE_POSITIVE
                    Suppressed:             true
                
                --------------------------------------------------------------------------------
                
                A summary of new vulnerabilities has been generated
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    private void validateNewPolicyViolationsSummaryNotificationPublish() {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.from()).containsExactly("dependencytrack@example.com");
        assertThat(message.subject()).isEqualTo("[Dependency-Track] New Policy Violations Summary");
        assertThat(message.content()).isEqualToIgnoringWhitespace("""
                New Policy Violations Summary
                
                --------------------------------------------------------------------------------
                
                Overview:
                - New Violations:      1 (Suppressed: 0)
                  - Of Type LICENSE: 1
                - Affected Projects:   1
                - Affected Components: 1
                - Since:               1970-01-01T00:01:06Z
                
                --------------------------------------------------------------------------------
                
                Project Summaries:
                
                - Project: [projectName : projectVersion]
                  Project URL: https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                  + New Violations Of Type LICENSE: 1 (Suppressed: 0)
                
                --------------------------------------------------------------------------------
                
                Violation Details:
                
                - Project: [projectName : projectVersion]
                  Project URL: https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                  + Policy:                policyName
                    Policy Condition:      AGE NUMERIC_EQUAL P666D
                    Policy Violation Type: LICENSE
                    Component:             componentName : componentVersion
                    Component URL:         https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                    Timestamp:             1970-01-01T18:31:06Z
                    Analysis State:        APPROVED
                    Suppressed:            false
                
                --------------------------------------------------------------------------------
                
                A summary of new policy violations has been generated
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z\
                """);
    }

    @Test
    void shouldSendHtmlBodyWhenTemplateMimeTypeIsHtml() throws Exception {
        final var htmlTemplate = new NotificationTemplate(/* language=HTML */ """
                <html><body><p>{{ notification.title }}</p></body></html>\
                """,
                "text/html; charset=utf-8");
        final NotificationTemplateRenderer htmlRenderer =
                new PebbleNotificationTemplateRendererFactory(
                        Map.of("baseUrl", () -> "https://example.com"))
                        .createRenderer(htmlTemplate);
        final var publishCtx =
                new NotificationPublishContext(
                        publishContext.ruleConfig(),
                        htmlRenderer);

        publisher.publish(publishCtx, createBomConsumedTestNotification());

        final MimeMessage[] messages = GREEN_MAIL.getReceivedMessages();
        assertThat(messages).hasSize(1);

        final MimeMessage message = messages[0];
        assertThat(message.getContentType()).isEqualToIgnoringCase("text/html; charset=utf-8");
        assertThat(message.isMimeType("text/html")).isTrue();
        assertThat((String) message.getContent()).isEqualTo(/* language=HTML */ """
                <html><body><p>Bill of Materials Consumed</p></body></html>\
                """);
    }

    private record ReceivedMessage(List<String> from, String subject, String content) {
    }

    private ReceivedMessage getReceivedMessage() {
        final MimeMessage[] messages = GREEN_MAIL.getReceivedMessages();
        assertThat(messages).hasSize(1);

        try {
            final MimeMessage message = messages[0];
            assertThat(message.isMimeType("text/plain")).isTrue();

            final Address[] from = message.getFrom();
            return new ReceivedMessage(
                    from != null
                            ? Arrays.stream(from).map(Address::toString).toList()
                            : List.of(),
                    message.getSubject(),
                    (String) message.getContent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (MessagingException e) {
            throw new IllegalStateException(e);
        }
    }

}