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
package org.dependencytrack.notification.publishing.webex;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.dependencytrack.notification.publishing.http.HttpNotificationPublisherRuleConfigV1;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

class WebexNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final WireMockExtension WIREMOCK = WireMockExtension.newInstance()
            .options(WireMockConfiguration.wireMockConfig().dynamicPort())
            .build();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new WebexNotificationPublisherFactory();
    }

    @Override
    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
        final var httpRuleConfig = (HttpNotificationPublisherRuleConfigV1) ruleConfig;
        httpRuleConfig.setDestinationUrl(URI.create(WIREMOCK.baseUrl()));
    }

    @BeforeEach
    @Override
    protected void beforeEach() throws Exception {
        super.beforeEach();

        WIREMOCK.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));
    }

    @Override
    protected void validateNotificationPublish(Notification notification) {
        switch (notification.getGroup()) {
            case GROUP_BOM_CONSUMED -> validateBomConsumedNotificationPublish();
            case GROUP_BOM_PROCESSING_FAILED -> validateBomProcessingFailedNotificationPublish();
            case GROUP_BOM_VALIDATION_FAILED -> validateBomValidationFailedNotificationPublish();
            case GROUP_NEW_VULNERABILITY -> validateNewVulnerabilityNotificationPublish();
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> validateNewVulnerableDependencyNotificationPublish();
        }
    }

    private void validateBomConsumedNotificationPublish() {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "markdown": "**Bill of Materials Consumed**\\n[View Component](https://example.com/component/?uuid=)\\n**Description:** A CycloneDX BOM was consumed and will be processed"
                        }
                        """)));
    }

    private void validateBomProcessingFailedNotificationPublish() {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "markdown": "**Bill of Materials Processing Failed**\\n[View Component](https://example.com/component/?uuid=)\\n**Description:** An error occurred while processing a BOM"
                        }
                        """)));
    }

    private void validateBomValidationFailedNotificationPublish() {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "markdown": "**Bill of Materials Validation Failed**\\n[View Component](https://example.com/component/?uuid=)\\n**Description:** An error occurred while validating a BOM"
                        }
                        """)));
    }

    private void validateNewVulnerabilityNotificationPublish() {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "markdown" : "**New Vulnerability Identified on Project: [projectName : projectVersion]**\\n**VulnID:** INT-001\\n**Severity:** MEDIUM\\n**Source:** INTERNAL\\n**Component:** componentName : componentVersion\\n**Actions:**\\n[View Vulnerability](https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001)\\n[View Component](https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6)\\n**Description:** vulnerabilityDescription"
                        }
                        """)));
    }

    private void validateNewVulnerableDependencyNotificationPublish() {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "markdown": "**Vulnerable Dependency Introduced on Project: [projectName : projectVersion]**\\n**Project:** projectName : projectVersion\\n**Component:** componentName : componentVersion\\n**Actions:**\\n[View Project](https://example.com/projects/?uuid=c9c9539a-e381-4b36-ac52-6a7ab83b2c95)\\n[View Component](https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6)\\n**Description:** A dependency was introduced that contains 1 known vulnerability"
                        }
                        """)));
    }

}