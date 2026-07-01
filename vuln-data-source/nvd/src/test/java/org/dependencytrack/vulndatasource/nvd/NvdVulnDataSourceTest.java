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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class NvdVulnDataSourceTest {

    private NvdVulnDataSource dataSource;
    private MockKeyValueStore kvStore;

    @AfterEach
    void afterEach() {
        if (dataSource != null) {
            dataSource.close();
        }
    }

    @Test
    void shouldIterateCvesFromModifiedFeed(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/gzip")
                        .withBody(gzip(/* language=JSON */ """
                                {
                                  "vulnerabilities": [
                                    {
                                      "cve": {
                                        "id": "CVE-2024-0001",
                                        "lastModified": "2024-01-01T00:00:00.000",
                                        "descriptions": [
                                          {
                                            "lang": "en",
                                            "value": "Test vulnerability"
                                          }
                                        ],
                                        "metrics": {}
                                      }
                                    }
                                  ]
                                }
                                """))));

        dataSource = createDataSource(wmRuntimeInfo.getHttpBaseUrl());

        assertThat(dataSource.hasNext()).isTrue();

        final Bom bov = dataSource.next();
        assertThat(bov).isNotNull();
        assertThat(bov.getVulnerabilitiesCount()).isEqualTo(1);

        final Vulnerability vuln = bov.getVulnerabilities(0);
        assertThat(vuln.getId()).isEqualTo("CVE-2024-0001");
        assertThat(vuln.getSource().getName()).isEqualTo("NVD");
        assertThat(vuln.getDescription()).isEqualTo("Test vulnerability");

        dataSource.markProcessed(bov);

        assertThat(dataSource.hasNext()).isFalse();
    }

    @Test
    void markProcessedShouldThrowWhenBovHasUnexpectedVulnCount(WireMockRuntimeInfo wmRuntimeInfo) {
        dataSource = createDataSource(wmRuntimeInfo.getHttpBaseUrl());

        final var bov = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-123"))
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-456"))
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dataSource.markProcessed(bov))
                .withMessage("BOV must have exactly one vulnerability, but has 2");
    }

    @Test
    void shouldSkipCvesBelowWatermark(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        kvStore = new MockKeyValueStore();
        kvStore.put("watermark", String.valueOf(Instant.parse("2024-06-01T00:00:00Z").toEpochMilli()));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2025-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/gzip")
                        .withBody(gzip(/* language=JSON */ """
                                {
                                  "vulnerabilities": [
                                    {
                                      "cve": {
                                        "id": "CVE-2024-0001",
                                        "lastModified": "2024-01-01T00:00:00.000",
                                        "descriptions": [{"lang": "en", "value": "Below watermark"}],
                                        "metrics": {}
                                      }
                                    },
                                    {
                                      "cve": {
                                        "id": "CVE-2024-0002",
                                        "lastModified": "2024-12-01T00:00:00.000",
                                        "descriptions": [{"lang": "en", "value": "Above watermark"}],
                                        "metrics": {}
                                      }
                                    }
                                  ]
                                }
                                """))));

        dataSource = createDataSource(
                wmRuntimeInfo.getHttpBaseUrl(),
                kvStore,
                List.of(new NvdDataFeed.ModifiedDataFeed()));

        assertThat(dataSource.hasNext()).isTrue();
        assertThat(dataSource.next().getVulnerabilities(0).getId()).isEqualTo("CVE-2024-0002");
        assertThat(dataSource.hasNext()).isFalse();
    }

    @Test
    void shouldSkipFeedWhenDigestUnchanged(WireMockRuntimeInfo wmRuntimeInfo) {
        kvStore = new MockKeyValueStore();
        kvStore.put(
                "feed-digest:modified",
                "0000000000000000000000000000000000000000000000000000000000000000");

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        dataSource = createDataSource(
                wmRuntimeInfo.getHttpBaseUrl(),
                kvStore,
                List.of(new NvdDataFeed.ModifiedDataFeed()));

        assertThat(dataSource.hasNext()).isFalse();
        verify(0, getRequestedFor(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz")));
    }

    @Test
    void shouldSkipFeedWhenBelowWatermark(WireMockRuntimeInfo wmRuntimeInfo) {
        kvStore = new MockKeyValueStore();
        kvStore.put("watermark", String.valueOf(Instant.parse("2024-06-01T00:00:00Z").toEpochMilli()));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        dataSource = createDataSource(
                wmRuntimeInfo.getHttpBaseUrl(),
                kvStore,
                List.of(new NvdDataFeed.ModifiedDataFeed()));

        assertThat(dataSource.hasNext()).isFalse();
        verify(0, getRequestedFor(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz")));
    }

    @Test
    void shouldCommitWatermarkOnClose(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        kvStore = new MockKeyValueStore();

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/gzip")
                        .withBody(gzip(/* language=JSON */ """
                                {
                                  "vulnerabilities": [
                                    {
                                      "cve": {
                                        "id": "CVE-2024-0001",
                                        "lastModified": "2024-01-01T00:00:00.000",
                                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                                        "metrics": {}
                                      }
                                    }
                                  ]
                                }
                                """))));

        dataSource = createDataSource(
                wmRuntimeInfo.getHttpBaseUrl(),
                kvStore,
                List.of(new NvdDataFeed.ModifiedDataFeed()));

        final Bom bov = dataSource.next();
        dataSource.markProcessed(bov);
        assertThat(dataSource.hasNext()).isFalse();

        dataSource.close();
        dataSource = null;

        final long expectedMillis = Timestamps.toMillis(bov.getVulnerabilities(0).getUpdated());
        assertThat(kvStore.get("watermark").value()).isEqualTo(String.valueOf(expectedMillis));
    }

    @Test
    void shouldCommitFeedDigestOnClose(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        kvStore = new MockKeyValueStore();

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));

        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/gzip")
                        .withBody(gzip(/* language=JSON */ """
                                {
                                  "vulnerabilities": [
                                    {
                                      "cve": {
                                        "id": "CVE-2024-0001",
                                        "lastModified": "2024-01-01T00:00:00.000",
                                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                                        "metrics": {}
                                      }
                                    }
                                  ]
                                }
                                """))));

        dataSource = createDataSource(
                wmRuntimeInfo.getHttpBaseUrl(),
                kvStore,
                List.of(new NvdDataFeed.ModifiedDataFeed()));

        while (dataSource.hasNext()) {
            dataSource.next();
        }

        dataSource.close();
        dataSource = null;

        assertThat(kvStore.get("feed-digest:modified").value())
                .isEqualTo("0000000000000000000000000000000000000000000000000000000000000000");
    }

    @Test
    void shouldThrowWhenMetadataResponseNotOk(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse().withStatus(500)));

        dataSource = createDataSource(wmRuntimeInfo.getHttpBaseUrl());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> dataSource.hasNext())
                .withMessage("Unexpected response code: 500");
    }

    @Test
    void shouldThrowWhenFeedDownloadNotOk(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                lastModifiedDate:2024-01-01T00:00:00.000Z
                                sha256:0000000000000000000000000000000000000000000000000000000000000000
                                """)));
        stubFor(get(urlEqualTo("/json/cve/2.0/nvdcve-2.0-modified.json.gz"))
                .willReturn(aResponse().withStatus(500)));

        dataSource = createDataSource(wmRuntimeInfo.getHttpBaseUrl());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> dataSource.hasNext())
                .withMessage("Unexpected response code: 500");
    }

    private NvdVulnDataSource createDataSource(String feedsUrl) {
        return createDataSource(
                feedsUrl,
                new MockKeyValueStore(),
                List.of(new NvdDataFeed.ModifiedDataFeed()));
    }

    private NvdVulnDataSource createDataSource(
            String feedsUrl,
            MockKeyValueStore kvStore,
            List<NvdDataFeed> feeds) {
        this.kvStore = kvStore;
        final var watermarkManager = new WatermarkManager(
                kvStore,
                feeds.stream().map(NvdDataFeed::name).toList());
        final ObjectMapper objectMapper = new ObjectMapper()
                .configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true)
                .configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true)
                .registerModule(new JavaTimeModule());

        return new NvdVulnDataSource(
                watermarkManager,
                objectMapper,
                HttpClient.newHttpClient(),
                feedsUrl,
                feeds);
    }

    private static byte[] gzip(String content) throws Exception {
        final var out = new ByteArrayOutputStream();
        try (final var gzipOut = new GZIPOutputStream(out)) {
            gzipOut.write(content.getBytes());
        }

        return out.toByteArray();
    }

}
