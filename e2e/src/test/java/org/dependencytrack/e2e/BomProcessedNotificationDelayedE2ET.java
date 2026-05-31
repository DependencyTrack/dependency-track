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
import org.dependencytrack.e2e.api.model.BomUploadRequest;
import org.dependencytrack.e2e.api.model.CreateNotificationRuleRequest;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.NotificationPublisher;
import org.dependencytrack.e2e.api.model.NotificationRule;
import org.dependencytrack.e2e.api.model.UpdateNotificationRuleRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class BomProcessedNotificationDelayedE2ET extends AbstractE2ET {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    @Override
    @BeforeEach
    void beforeEach() throws Exception {
        // host.docker.internal may not always be available, so use testcontainer's
        // solution for host port exposure instead: https://www.testcontainers.org/features/networking/#exposing-host-ports-to-the-container
        Testcontainers.exposeHostPorts(wireMock.getRuntimeInfo().getHttpPort());

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(final GenericContainer<?> container) {
        container.withEnv("DT_TMP_DELAY_BOM_PROCESSED_NOTIFICATION", "true");
    }

    @Test
    void test() throws Exception {
        final List<NotificationPublisher> publishers = apiClient.getAllNotificationPublishers();

        // Find the webhook notification publisher.
        final NotificationPublisher webhookPublisher = publishers.stream()
                .filter(publisher -> publisher.name().equals("Webhook"))
                .findAny()
                .orElseThrow(() -> new AssertionError("Unable to find webhook notification publisher"));

        // Create a webhook alert for NEW_VULNERABILITY notifications and point it to WireMock.
        final NotificationRule webhookRule = apiClient.createNotificationRule(new CreateNotificationRuleRequest(
                "foo", "PORTFOLIO", "INFORMATIONAL", new CreateNotificationRuleRequest.Publisher(webhookPublisher.uuid())));
        apiClient.updateNotificationRule(new UpdateNotificationRuleRequest(webhookRule.uuid(), webhookRule.name(), true, "PORTFOLIO",
                "INFORMATIONAL", Set.of("BOM_PROCESSED"), /* language=JSON */ """
                {
                  "destinationUrl": "http://host.testcontainers.internal:%d/notification"
                }
                """.formatted(wireMock.getPort())));

        wireMock.stubFor(post(urlPathEqualTo("/notification"))
                .willReturn(aResponse()
                        .withStatus(201)));

        // Create a new internal vulnerability for jackson-databind.
        apiClient.createVulnerability(new CreateVulnerabilityRequest("INT-123", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", List.of(917, 502), List.of(
                new CreateVulnerabilityRequest.AffectedComponent("PURL", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2.2", "EXACT")
        )));

        // Parse and base64 encode a BOM.
        final byte[] bomBytes = getClass().getResourceAsStream("/dtrack-apiserver-4.5.0.bom.json").readAllBytes();
        final String bomBase64 = Base64.getEncoder().encodeToString(bomBytes);

        // Upload the BOM
        final EventTokenResponse response = apiClient.uploadBom(new BomUploadRequest("foo", "bar", true, bomBase64));
        assertThat(response.token()).isNotEmpty();

        // Wait up to 15sec for the BOM processing to complete.
        await("BOM_PROCESSED webhook notification")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(this::verifyBomProcessedWebhookNotification);
    }

    private void verifyBomProcessedWebhookNotification() {
        wireMock.verify(1, postRequestedFor(urlPathEqualTo("/notification"))
                .withRequestBody(equalToJson("""
                        {
                          "notification" : {
                            "id" : "${json-unit.any-string}",
                            "level" : "LEVEL_INFORMATIONAL",
                            "scope" : "SCOPE_PORTFOLIO",
                            "group" : "GROUP_BOM_PROCESSED",
                            "timestamp" : "${json-unit.regex}(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\\\.[0-9]{3}Z$)",
                            "title" : "Bill of Materials Processed",
                            "content" : "A CycloneDX BOM was processed",
                            "subject" : {
                              "token": "${json-unit.any-string}",
                              "project" : {
                                "uuid" : "${json-unit.any-string}",
                                "name" : "foo",
                                "version" : "bar",
                                "purl" : "pkg:maven/org.dependencytrack/dependency-track@4.5.0?type=war",
                                "isActive" : true
                              },
                              "bom" : {
                                "content" : "(Omitted)",
                                "format" : "CycloneDX",
                                "specVersion" : "Unknown"
                              }
                            }
                          }
                        }
                        """)));
    }
}
