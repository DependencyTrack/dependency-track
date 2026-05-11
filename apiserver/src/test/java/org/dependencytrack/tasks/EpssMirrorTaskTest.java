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

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.model.Epss;
import org.dependencytrack.persistence.jdbi.EpssDao;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.net.http.HttpClient;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_FEEDS_URL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class EpssMirrorTaskTest extends PersistenceCapableTest {

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
    void shouldMirrorEpssRecords() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        final var compressedFeedOutputStream = new ByteArrayOutputStream();
        try (final var gzipOutputStream = new GZIPOutputStream(compressedFeedOutputStream)) {
            gzipOutputStream.write(/* language=CSV */ """
                    #model_version:v2025.03.14,score_date:2025-09-24T12:55:00Z
                    cve,epss,percentile
                    CVE-1999-0001,0.01141,0.7769
                    CVE-1999-0002,0.15347,0.94405
                    CVE-1999-0003,0.90362,0.99581\
                    """.getBytes());
        }

        wireMock.stubFor(get(urlPathEqualTo("/epss_scores-current.csv.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(compressedFeedOutputStream.toByteArray())));

        // Create an existing EPSS record for CVE-1999-0001.
        // It must be updated as part of the mirroring operation.
        useJdbiHandle(handle -> handle.attach(EpssDao.class)
                .createOrUpdateAll(List.of(new Epss("CVE-1999-0001", BigDecimal.ONE, BigDecimal.ZERO))));

        new EpssMirrorTask(httpClient).inform(new EpssMirrorEvent());

        final List<Epss> epssRecords = findAllEpss();

        assertThat(epssRecords).satisfiesExactlyInAnyOrder(
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0001");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.01141");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.7769");
                },
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0002");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.15347");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.94405");
                },
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0003");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.90362");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.99581");
                });
    }

    @Test
    void shouldFailOnMalformedFeed() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        final var compressedFeedOutputStream = new ByteArrayOutputStream();
        try (final var gzipOutputStream = new GZIPOutputStream(compressedFeedOutputStream)) {
            gzipOutputStream.write(/* language=CSV */ """
                    cve,epss,percentile
                    CVE-1999-0001,0.01141,0.7769,doesNotBelongHere
                    CVE-1999-0002,0.15347,0.94405\
                    """.getBytes());
        }

        wireMock.stubFor(get(urlPathEqualTo("/epss_scores-current.csv.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(compressedFeedOutputStream.toByteArray())));

        new EpssMirrorTask(httpClient).inform(new EpssMirrorEvent());

        assertThat(findAllEpss()).isEmpty();
    }

    @Test
    void shouldNotExecuteWhenDisabled() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "false",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDefaultPropertyValue(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        new EpssMirrorTask(httpClient).inform(new EpssMirrorEvent());

        assertThat(findAllEpss()).isEmpty();
    }

    private static List<Epss> findAllEpss() {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "CVE" AS "cve"
                             , "SCORE" AS "score"
                             , "PERCENTILE" AS "percentile"
                          FROM "EPSS"
                        """)
                .map(BeanMapper.of(Epss.class))
                .list());
    }

}