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
package org.dependencytrack.tasks;

import alpine.model.ConfigProperty;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.http.HttpClient;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_DATA;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_SUBMISSION_ENABLED;

class TelemetrySubmissionTaskTest extends PersistenceCapableTest {

    @RegisterExtension
    private static final WireMockExtension wireMock =
            WireMockExtension.newInstance()
                    .options(options().dynamicPort())
                    .build();

    private static HttpClient httpClient;

    @BeforeAll
    static void beforeAll() {
        httpClient = HttpClient.newHttpClient();
    }

    @AfterAll
    static void afterAll() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    void shouldSubmitTelemetryWhenEnabledAndDue() {
        createTelemetryConfigProperties("true", null);

        wireMock.stubFor(post(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(200)));

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(postRequestedFor(urlEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                            "system_id": "${json-unit.any-string}",
                            "dt_version": "999-SNAPSHOT",
                            "db_type": "${json-unit.any-string}",
                            "db_version": "${json-unit.any-string}"
                        }
                        """)));

        qm.getPersistenceManager().evictAll();
        final ConfigProperty lastSubmissionEpoch = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmissionEpoch).isNotNull();
        assertThat(lastSubmissionEpoch.getPropertyValue()).isNotNull();

        final ConfigProperty lastSubmissionData = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
        assertThat(lastSubmissionData).isNotNull();
        assertThatJson(lastSubmissionData.getPropertyValue()).isEqualTo("""
                {
                    "system_id": "${json-unit.any-string}",
                    "dt_version": "999-SNAPSHOT",
                    "db_type": "${json-unit.any-string}",
                    "db_version": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldNotSubmitWhenDisabled() {
        createTelemetryConfigProperties("false", null);

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(0, postRequestedFor(urlEqualTo("/")));
    }

    @Test
    void shouldNotSubmitWhenDevProfileActive() {
        createTelemetryConfigProperties("true", null);

        final Config config = new SmallRyeConfigBuilder()
                .withProfile("dev")
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(0, postRequestedFor(urlEqualTo("/")));
    }

    @Test
    void shouldNotSubmitWhenLastSubmissionIsRecent() {
        final String recentEpoch = String.valueOf(Instant.now().getEpochSecond());
        createTelemetryConfigProperties("true", recentEpoch);

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(0, postRequestedFor(urlEqualTo("/")));
    }

    @Test
    void shouldNotRecordSubmissionOn429() {
        createTelemetryConfigProperties("true", null);

        wireMock.stubFor(post(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(429)));

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(postRequestedFor(urlEqualTo("/")));

        final ConfigProperty lastSubmissionEpoch = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmissionEpoch.getPropertyValue()).isNull();
    }

    @Test
    void shouldNotRecordSubmissionOnServerError() {
        createTelemetryConfigProperties("true", null);

        wireMock.stubFor(post(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(500)));

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.version", "999-SNAPSHOT")
                .build();
        new TelemetrySubmissionTask(httpClient, config, wireMock.baseUrl() + "/").run();

        wireMock.verify(postRequestedFor(urlEqualTo("/")));

        final ConfigProperty lastSubmissionEpoch = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmissionEpoch.getPropertyValue()).isNull();
    }

    private void createTelemetryConfigProperties(String enabled, String lastSubmissionEpoch) {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                enabled,
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());
        qm.createConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName(),
                lastSubmissionEpoch,
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyType(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getDescription());
        qm.createConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName(),
                null,
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyType(),
                TELEMETRY_LAST_SUBMISSION_DATA.getDescription());
    }

}
