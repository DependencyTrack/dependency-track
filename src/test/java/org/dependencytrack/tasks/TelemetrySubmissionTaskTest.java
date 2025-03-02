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
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.TelemetrySubmissionEvent;
import org.junit.Rule;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_DATA;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_SUBMISSION_ENABLED;

public class TelemetrySubmissionTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @Test
    public void shouldSubmitTelemetryDataWhenEnabled() {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                "true",
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());

        wireMock.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));

        new TelemetrySubmissionTask(wireMock.baseUrl()).inform(new TelemetrySubmissionEvent());

        wireMock.verify(postRequestedFor(urlPathEqualTo("/"))
                .withRequestBody(equalToJson("""
                        {
                          "system_id": "${json-unit.any-string}",
                          "dt_version": "${json-unit.any-string}",
                          "db_type": "H2",
                          "db_version": "${json-unit.any-string}"
                        }
                        """)));

        final ConfigProperty lastSubmittedTimestampProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmittedTimestampProperty.getPropertyValue()).isNotNull();

        final ConfigProperty lastSubmittedDataProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
        assertThatJson(lastSubmittedDataProperty.getPropertyValue()).isEqualTo(/* language=JSON */ """
                {
                  "system_id": "${json-unit.any-string}",
                  "dt_version": "${json-unit.any-string}",
                  "db_type": "H2",
                  "db_version": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void shouldNotSubmitTelemetryDataWhenDisabled() {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                "false",
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());

        wireMock.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));

        new TelemetrySubmissionTask(wireMock.baseUrl()).inform(new TelemetrySubmissionEvent());

        wireMock.verify(0, anyRequestedFor(anyUrl()));

        final ConfigProperty lastSubmittedTimestampProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmittedTimestampProperty).isNull();

        final ConfigProperty lastSubmittedDataProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
        assertThat(lastSubmittedDataProperty).isNull();
    }

    @Test
    public void shouldNotSubmitTelemetryDataWhenLastSubmittedWithinOneDay() {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                "true",
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());

        final String lastSubmittedEpochSeconds = String.valueOf(
                Instant.now().minus(23, ChronoUnit.HOURS).getEpochSecond());
        qm.createConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName(),
                lastSubmittedEpochSeconds,
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyType(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getDescription());

        wireMock.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));

        new TelemetrySubmissionTask(wireMock.baseUrl()).inform(new TelemetrySubmissionEvent());

        wireMock.verify(0, anyRequestedFor(anyUrl()));

        final ConfigProperty lastSubmittedTimestampProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmittedTimestampProperty.getPropertyValue()).isEqualTo(lastSubmittedEpochSeconds);

        final ConfigProperty lastSubmittedDataProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
        assertThat(lastSubmittedDataProperty).isNull();
    }

    @Test
    public void shouldFollowRedirect() {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                "true",
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());

        wireMock.stubFor(post(urlPathEqualTo("/"))
                .willReturn(aResponse()
                        .withStatus(308)
                        .withHeader("Location", wireMock.url("/foo"))));
        wireMock.stubFor(post(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(200)));

        new TelemetrySubmissionTask(wireMock.baseUrl()).inform(new TelemetrySubmissionEvent());

        wireMock.verify(postRequestedFor(urlPathEqualTo("/"))
                .withRequestBody(equalToJson("""
                        {
                          "system_id": "${json-unit.any-string}",
                          "dt_version": "${json-unit.any-string}",
                          "db_type": "H2",
                          "db_version": "${json-unit.any-string}"
                        }
                        """)));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/foo"))
                .withRequestBody(equalToJson("""
                        {
                          "system_id": "${json-unit.any-string}",
                          "dt_version": "${json-unit.any-string}",
                          "db_type": "H2",
                          "db_version": "${json-unit.any-string}"
                        }
                        """)));
    }

    @Test
    public void shouldNotRecordSubmittedTelemetryDataWhenRateLimited() {
        qm.createConfigProperty(
                TELEMETRY_SUBMISSION_ENABLED.getGroupName(),
                TELEMETRY_SUBMISSION_ENABLED.getPropertyName(),
                "true",
                TELEMETRY_SUBMISSION_ENABLED.getPropertyType(),
                TELEMETRY_SUBMISSION_ENABLED.getDescription());

        wireMock.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(429)));

        new TelemetrySubmissionTask(wireMock.baseUrl()).inform(new TelemetrySubmissionEvent());

        wireMock.verify(postRequestedFor(urlPathEqualTo("/"))
                .withRequestBody(equalToJson("""
                        {
                          "system_id": "${json-unit.any-string}",
                          "dt_version": "${json-unit.any-string}",
                          "db_type": "H2",
                          "db_version": "${json-unit.any-string}"
                        }
                        """)));

        final ConfigProperty lastSubmittedTimestampProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        assertThat(lastSubmittedTimestampProperty).isNull();

        final ConfigProperty lastSubmittedDataProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
        assertThatJson(lastSubmittedDataProperty).isNull();
    }

}