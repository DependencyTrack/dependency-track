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
package org.dependencytrack.kevdatasource.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class VulnCheckKevDataSourceTest {

    private static final String API_TOKEN = "vulncheck_abc123";

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void shouldParseVulnCheckKevBackup(WireMockRuntimeInfo wmRuntimeInfo) {
        stubBackup(wmRuntimeInfo, createBackupArchive(/* language=JSON */ """
                [
                  {
                    "vendorProject": "Apache",
                    "product": "Log4j2",
                    "shortDescription": "Log4Shell",
                    "required_action": "Apply updates",
                    "knownRansomwareCampaignUse": "Known",
                    "cve": [
                      "CVE-2021-44228",
                      "CVE-2021-45046"
                    ],
                    "date_added": "2021-12-10T00:00:00Z"
                  },
                  {
                    "vendorProject": "Citrix",
                    "product": "NetScaler ADC",
                    "shortDescription": "Code injection",
                    "required_action": "Apply updates",
                    "knownRansomwareCampaignUse": "Unknown",
                    "cve": ["CVE-2023-3519"],
                    "date_added": "2023-07-19T14:22:11Z"
                  }
                ]
                """));

        try (final KevDataSource dataSource = createDataSource(wmRuntimeInfo)) {
            assertThat(dataSource)
                    .toIterable()
                    .satisfiesExactly(
                            assertion -> {
                                assertThat(assertion.vulnSource()).isEqualTo("NVD");
                                assertThat(assertion.vulnId()).isEqualTo("CVE-2021-44228");
                                assertThat(assertion.publishedAt()).isEqualTo(Instant.parse("2021-12-10T00:00:00Z"));
                                assertThat(assertion.requiredAction()).isEqualTo("Apply updates");
                                assertThat(assertion.knownRansomware()).isTrue();
                                assertThat(assertion.description()).isEqualTo("Log4Shell");
                                assertThat(assertion.raw().get("product").asText())
                                        .isEqualTo("Log4j2");
                            },
                            assertion -> {
                                assertThat(assertion.vulnId()).isEqualTo("CVE-2021-45046");
                                assertThat(assertion.knownRansomware()).isTrue();
                                assertThat(assertion.raw().get("product").asText())
                                        .isEqualTo("Log4j2");
                            },
                            assertion -> {
                                assertThat(assertion.vulnId()).isEqualTo("CVE-2023-3519");
                                assertThat(assertion.publishedAt()).isEqualTo(Instant.parse("2023-07-19T14:22:11Z"));
                                assertThat(assertion.knownRansomware()).isNull();
                            });
        }
    }

    @Test
    void shouldSkipEntriesWithoutCve(WireMockRuntimeInfo wmRuntimeInfo) {
        stubBackup(wmRuntimeInfo, createBackupArchive(/* language=JSON */ """
                [
                  {
                    "shortDescription": "Empty CVE array",
                    "cve": [],
                    "date_added": "2024-01-01T00:00:00Z"
                  },
                  {
                    "shortDescription": "No CVE field",
                    "date_added": "2024-01-01T00:00:00Z"
                  },
                  {
                    "shortDescription": "Has CVE",
                    "cve": ["CVE-2023-3519"],
                    "date_added": "2024-01-01T00:00:00Z"
                  }
                ]
                """));

        try (final KevDataSource dataSource = createDataSource(wmRuntimeInfo)) {
            assertThat(dataSource)
                    .toIterable()
                    .satisfiesExactly(
                            assertion -> assertThat(assertion.vulnId()).isEqualTo("CVE-2023-3519"));
        }
    }

    @Test
    void shouldNotSendApiTokenToDownloadHost(WireMockRuntimeInfo wmRuntimeInfo) {
        stubBackup(wmRuntimeInfo, createBackupArchive(/* language=JSON */ """
                [
                  {
                    "cve": ["CVE-2023-3519"],
                    "date_added": "2023-07-19T14:22:11Z"
                  }
                ]
                """));

        try (final var dataSource = createDataSource(wmRuntimeInfo)) {
            assertThat(dataSource).toIterable().hasSize(1);
        }

        verify(getRequestedFor(urlEqualTo("/v3/backup/vulncheck-kev"))
                .withHeader("Authorization", equalTo("Bearer " + API_TOKEN)));
        verify(getRequestedFor(urlEqualTo("/backup.zip")).withoutHeader("Authorization"));
    }

    @Test
    void shouldFailOnSha256Mismatch(WireMockRuntimeInfo wmRuntimeInfo) {
        final byte[] zipBytes = createBackupArchive(/* language=JSON */ """
                [
                  {
                    "cve": ["CVE-2023-3519"],
                    "date_added": "2023-07-19T14:22:11Z"
                  }
                ]
                """);
        stubBackupWithDigest(wmRuntimeInfo, zipBytes, "0".repeat(64));

        try (final KevDataSource dataSource = createDataSource(wmRuntimeInfo)) {
            assertThatThrownBy(dataSource::hasNext)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("checksum")
                    .hasMessageNotContaining(API_TOKEN);
        }
    }

    @Test
    void shouldFailOnUnexpectedResponseCode(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/v3/backup/vulncheck-kev"))
                .willReturn(aResponse().withStatus(401).withBody("token is not authorized")));

        try (final KevDataSource dataSource = createDataSource(wmRuntimeInfo)) {
            assertThatThrownBy(dataSource::hasNext)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("401");
        }
    }

    @Test
    void shouldRefuseInsecureDownloadUrl(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/v3/backup/vulncheck-kev"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                        {
                          "data": [
                            {
                              "sha256": "%s",
                              "url": "file:///etc/passwd"
                            }
                          ]
                        }
                        """.formatted("0".repeat(64)))));

        try (final KevDataSource dataSource = createDataSource(wmRuntimeInfo)) {
            assertThatThrownBy(dataSource::hasNext)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("insecure URL");
        }
    }

    private VulnCheckKevDataSource createDataSource(WireMockRuntimeInfo wmRuntimeInfo) {
        return new VulnCheckKevDataSource(
                HttpClient.newHttpClient(), objectMapper, URI.create(wmRuntimeInfo.getHttpBaseUrl()), API_TOKEN);
    }

    private static void stubBackup(WireMockRuntimeInfo wmRuntimeInfo, byte[] zipBytes) {
        stubBackupWithDigest(wmRuntimeInfo, zipBytes, sha256Hex(zipBytes));
    }

    private static void stubBackupWithDigest(WireMockRuntimeInfo wmRuntimeInfo, byte[] zipBytes, String sha256) {
        stubFor(get(urlEqualTo("/v3/backup/vulncheck-kev"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                        {
                          "_meta": {
                            "index": "vulncheck-kev"
                          },
                          "data": [
                            {
                              "filename": "vulncheck-kev-1693513207700526476.zip",
                              "sha256": "%s",
                              "url": "%s/backup.zip",
                              "url_ttl_minutes": 60
                            }
                          ]
                        }
                        """.formatted(sha256, wmRuntimeInfo.getHttpBaseUrl()))));

        stubFor(get(urlEqualTo("/backup.zip"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/zip")
                        .withBody(zipBytes)));
    }

    private static byte[] createBackupArchive(String contentJson) {
        final var byteStream = new ByteArrayOutputStream();
        try (final var zipStream = new ZipOutputStream(byteStream)) {
            zipStream.putNextEntry(new ZipEntry("vulncheck-kev.json"));
            zipStream.write(contentJson.getBytes(UTF_8));
            zipStream.closeEntry();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return byteStream.toByteArray();
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
