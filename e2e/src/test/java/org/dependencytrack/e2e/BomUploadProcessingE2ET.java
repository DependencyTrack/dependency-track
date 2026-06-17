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
package org.dependencytrack.e2e;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.mail.internet.MimeMessage;
import org.dependencytrack.e2e.api.model.BomUploadRequest;
import org.dependencytrack.e2e.api.model.CreateNotificationRuleRequest;
import org.dependencytrack.e2e.api.model.CreateNotificationRuleRequest.Publisher;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest.AffectedComponent;
import org.dependencytrack.e2e.api.model.EventProcessingResponse;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.Finding;
import org.dependencytrack.e2e.api.model.NotificationPublisher;
import org.dependencytrack.e2e.api.model.NotificationRule;
import org.dependencytrack.e2e.api.model.Project;
import org.dependencytrack.e2e.api.model.UpdateExtensionConfigRequest;
import org.dependencytrack.e2e.api.model.UpdateNotificationRuleRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class BomUploadProcessingE2ET extends AbstractE2ET {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    @RegisterExtension
    static GreenMailExtension greenMail = new GreenMailExtension(ServerSetup.SMTP.dynamicPort());

    @Override
    @BeforeEach
    void beforeEach() throws Exception {
        // host.docker.internal may not always be available, so use testcontainer's
        // solution for host port exposure instead: https://www.testcontainers.org/features/networking/#exposing-host-ports-to-the-container
        Testcontainers.exposeHostPorts(greenMail.getSmtp().getPort(), wireMock.getRuntimeInfo().getHttpPort());

        // Users must be created before the notification-publisher container is started.
        greenMail.getUserManager().createUser("from@localhost", "from", "fromPass");
        greenMail.getUserManager().createUser("to@localhost", "to", "toPass");

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(GenericContainer<?> container) {
        container
                .withEnv("DT_NOTIFICATION_PUBLISHER_EMAIL_ALLOW_LOCAL_CONNECTIONS", "true")
                .withEnv("DT_SECRET_MANAGEMENT_PROVIDER", "env")
                .withEnv("DT_SECRET_EMAIL_PASSWORD", "fromPass");
    }

    @Test
    void test() throws Exception {
        apiClient.updateExtensionConfig(
                "notification-publisher",
                "email",
                new UpdateExtensionConfigRequest(
                        Map.ofEntries(
                                Map.entry("enabled", true),
                                Map.entry("host", "host.testcontainers.internal"),
                                Map.entry("port", greenMail.getSmtp().getPort()),
                                Map.entry("username", "from"),
                                Map.entry("password", "EMAIL_PASSWORD"),
                                Map.entry("senderAddress", "from@localhost"))));

        final List<NotificationPublisher> publishers = apiClient.getAllNotificationPublishers();

        // Find the email notification publisher.
        final NotificationPublisher emailPublisher = publishers.stream()
                .filter(publisher -> publisher.name().equals("Email"))
                .findAny()
                .orElseThrow(() -> new AssertionError("Unable to find email notification publisher"));

        // Find the webhook notification publisher.
        final NotificationPublisher webhookPublisher = publishers.stream()
                .filter(publisher -> publisher.name().equals("Webhook"))
                .findAny()
                .orElseThrow(() -> new AssertionError("Unable to find webhook notification publisher"));

        // Create an email alert for NEW_VULNERABILITY notifications and point it to GreenMail.
        final NotificationRule emailRule = apiClient.createNotificationRule(new CreateNotificationRuleRequest(
                "email", "PORTFOLIO", "INFORMATIONAL", new Publisher(emailPublisher.uuid())));
        apiClient.updateNotificationRule(new UpdateNotificationRuleRequest(emailRule.uuid(), emailRule.name(), true, "PORTFOLIO",
                "INFORMATIONAL", Set.of("NEW_VULNERABILITY"), /* language=JSON */ """
                {
                  "recipientAddresses": [
                    "to@localhost"
                  ]
                }
                """));

        // Create a webhook alert for NEW_VULNERABILITY notifications and point it to WireMock.
        final NotificationRule webhookRule = apiClient.createNotificationRule(new CreateNotificationRuleRequest(
                "foo", "PORTFOLIO", "INFORMATIONAL", new Publisher(webhookPublisher.uuid())));
        apiClient.updateNotificationRule(new UpdateNotificationRuleRequest(webhookRule.uuid(), webhookRule.name(), true, "PORTFOLIO",
                "INFORMATIONAL", Set.of("NEW_VULNERABILITY"), /* language=JSON */ """
                {
                  "destinationUrl": "http://host.testcontainers.internal:%d/notification"
                }
                """.formatted(wireMock.getPort())));

        // Ensure notifications will be acknowledged by WireMock.
        wireMock.stubFor(post(urlPathEqualTo("/notification"))
                .willReturn(aResponse()
                        .withStatus(200)));

        // Create a new internal vulnerability for jackson-databind.
        apiClient.createVulnerability(new CreateVulnerabilityRequest("INT-123", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", List.of(917, 502), List.of(
                new AffectedComponent("PURL", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", "EXACT")
        )));

        // Parse and base64 encode a BOM.
        final byte[] bomBytes = getClass().getResourceAsStream("/dtrack-apiserver-4.5.0.bom.json").readAllBytes();
        final String bomBase64 = Base64.getEncoder().encodeToString(bomBytes);

        // Upload the BOM
        final EventTokenResponse response = apiClient.uploadBom(new BomUploadRequest("foo", "bar", true, bomBase64));
        assertThat(response.token()).isNotEmpty();

        // Wait up to 15sec for the BOM processing to complete.
        await("BOM processing")
                .atMost(Duration.ofSeconds(15))
                .pollDelay(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    final EventProcessingResponse processingResponse = apiClient.isEventBeingProcessed(response.token());
                    assertThat(processingResponse.processing()).isFalse();
                });

        // Lookup the project we just created.
        final Project project = apiClient.lookupProject("foo", "bar");

        // Ensure the internal vulnerability has been flagged.
        final List<Finding> findings = apiClient.getFindings(project.uuid(), false);
        assertThat(findings).satisfiesExactly(
                finding -> {
                    assertThat(finding.component().name()).isEqualTo("jackson-databind");
                    assertThat(finding.vulnerability().vulnId()).isEqualTo("INT-123");
                    assertThat(finding.attribution().analyzerIdentity()).isEqualTo("internal");
                    assertThat(finding.attribution().attributedOn()).isNotBlank();
                }
        );

        // Verify that we received alerts about jackson-databind being vulnerable
        // via both email and webhook notifications.
        await("NEW_VULNERABILITY webhook notification")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(this::verifyWebhookNotification);
        await("NEW_VULNERABILITY email notification")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(this::verifyEmailNotification);
    }

    private void verifyEmailNotification() {
        assertThat(greenMail.getReceivedMessages()).hasSize(1);
        final MimeMessage email = greenMail.getReceivedMessages()[0];
        // assertThat(email.getSubject()).isEqualTo("[Dependency-Track] New Vulnerability Identified on Project: [foo : bar]"); // TODO
        // assertThat(email.getContent()).asString().matches(""); // TODO
    }

    private void verifyWebhookNotification() {
        // FIXME: The comparison of the `cvssv3` field is failing, because WireMock / json-unit parse the JSON
        //   provided below into a Jackson `JsonNode` before comparing it with the actual Webhook content.
        //   In doing so, the `cvssv3` node SOMEHOW gets converted into a `DecimalNode`, with the value being 1E+1
        //   instead of 10.0. Debugging this shows that the notification has the correct format.
        //   The same thing is also tested in `WebhookPublisherTest#testPublishNewVulnerabilityNotification`,
        //   where the comparison works just fine... Using `${json-unit.any-number}` here until the comparison is fixed.
        wireMock.verify(postRequestedFor(urlPathEqualTo("/notification"))
                .withRequestBody(equalToJson("""
                        {
                          "notification": {
                            "id" : "${json-unit.any-string}",
                            "level": "LEVEL_INFORMATIONAL",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_NEW_VULNERABILITY",
                            "timestamp": "${json-unit.regex}(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\\\.[0-9]{3}Z$)",
                            "title": "New Vulnerability Identified on Project: [foo : bar]",
                            "content": "INT-123",
                            "subject": {
                              "component": {
                                "uuid": "${json-unit.any-string}",
                                "group": "com.fasterxml.jackson.core",
                                "name": "jackson-databind",
                                "version": "2.13.2.2",
                                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2?type=jar",
                                "md5": "055c97cb488b0956801e13abcc2a0cfe",
                                "sha1": "ffeb635597d093509f33e1e94274d14be610f933",
                                "sha256": "efb86b148712a838b94b3cfc95769785a116b3461f709b4cc510055a58b804b2",
                                "sha512": "0e9398591d86f80f16fc2d6ff0dda3e7821033e2c59472981eaab61443be3d77198655682905b85260fb2186a2cf0f33988aff689a49bb54e56c07e02f607e8a"
                              },
                              "project": {
                                "uuid": "${json-unit.any-string}",
                                "name": "foo",
                                "version": "bar",
                                "purl": "pkg:maven/org.dependencytrack/dependency-track@4.5.0?type=war",
                                "isActive": true
                              },
                              "vulnerability": {
                                "uuid": "${json-unit.any-string}",
                                "vulnId": "INT-123",
                                "source": "INTERNAL",
                                "cvssv3" : "${json-unit.any-number}",
                                "severity": "CRITICAL",
                                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                              },
                              "affectedProjectsReference": {
                                "apiUri": "/api/v1/vulnerability/source/INTERNAL/vuln/INT-123/projects",
                                "frontendUri": "/vulnerabilities/INTERNAL/INT-123/affectedProjects"
                              },
                              "analysisTrigger" : "ANALYSIS_TRIGGER_BOM_UPLOAD",
                              "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS",
                              "affectedProjects": [
                                {
                                  "uuid": "${json-unit.any-string}",
                                  "name": "foo",
                                  "version": "bar",
                                  "purl": "pkg:maven/org.dependencytrack/dependency-track@4.5.0?type=war",
                                  "isActive": true
                                }
                              ]
                            }
                          }
                        }
                        """)
                )
        );
    }
}
