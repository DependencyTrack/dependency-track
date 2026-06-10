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
package org.dependencytrack.vulndatasource.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WireMockTest
class OsvVulnDataSourceTest {

    private WatermarkManager watermarkManagerMock;
    private OsvVulnDataSource vulnDataSource;
    private ObjectMapper objectMapper;

    @BeforeEach
    void beforeEach() {
        watermarkManagerMock = mock(WatermarkManager.class);
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        vulnDataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                "http://localhost",
                List.of("maven"),
                mock(HttpClient.class),
                false
        );
    }

    @Test
    void testAdvanceWatermarkWhenProcessed() {
        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder()
                        .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                        .addProperties(Property.newBuilder()
                                .setName(CycloneDxPropertyNames.OSV_ECOSYSTEM)
                                .setValue("maven"))
                        .build())
                .build();

        vulnDataSource.markProcessed(bom);
        verify(watermarkManagerMock)
                .maybeAdvance(eq("maven"), eq(updatedAt));
    }

    @Test
    void testExceptionWithMultipleVulns() {
        Vulnerability v1 = Vulnerability.newBuilder().build();
        Vulnerability v2 = Vulnerability.newBuilder().build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(v1)
                .addVulnerabilities(v2)
                .build();

        assertThatThrownBy(() -> vulnDataSource.markProcessed(bom))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("BOV must have exactly one vulnerability, but has 2");
    }

    @Test
    void testExceptionWhenMissingEcosystem() {
        Instant updatedAt = Instant.parse("2024-01-01T12:00:00Z");

        Vulnerability vuln = Vulnerability.newBuilder()
                .setUpdated(Timestamps.fromMillis(updatedAt.toEpochMilli()))
                .build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(vuln)
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> vulnDataSource.markProcessed(bom));
    }

    @Test
    void testNoExceptionWhenMissingUpdated() {
        Vulnerability vuln = Vulnerability.newBuilder()
                .addProperties(Property.newBuilder()
                        .setName(CycloneDxPropertyNames.OSV_ECOSYSTEM)
                        .setValue("maven"))
                .build();

        Bom bom = Bom.newBuilder()
                .addVulnerabilities(vuln)
                .build();

        assertThatNoException()
                .isThrownBy(() -> vulnDataSource.markProcessed(bom));

        verify(watermarkManagerMock, never()).maybeAdvance(eq("maven"), any(Instant.class));
    }

    @Test
    void testCloseWithCompletedEcosystems() {
        vulnDataSource.close();
        verify(watermarkManagerMock).maybeCommit(any(Set.class));
    }

    @Test
    void shouldIterateAdvisoriesFromFullArchive(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final String ecosystem = "maven";

        // Create in-memory ZIP with one advisory JSON
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = /* language=JSON */ """
                    {
                        "id": "OSV-789",
                        "summary": "Test vulnerability",
                        "affected": [],
                        "modified": "2022-06-09T07:01:32.587Z"
                    }
                    """;
            zos.write(advisoryJson.getBytes());
            zos.closeEntry();
        }

        stubFor(get(urlEqualTo("/" + ecosystem + "/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(zipBytes.toByteArray())
                        .withHeader("Content-Type", "application/zip")));

        OsvVulnDataSource dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of(ecosystem),
                HttpClient.newHttpClient(),
                false
        );

        assertTrue(dataSource.hasNext());
        var bom = dataSource.next();
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "vulnerabilities": [
                            {
                              "id":"OSV-789",
                              "source":{
                                "name":"OSV"
                              },
                              "ratings": [
                                {
                                  "severity":"SEVERITY_UNKNOWN"
                                }
                              ],
                              "updated":"2022-06-09T07:01:32.587Z",
                              "properties": [
                                {
                                  "name":"dependency-track:vuln:title",
                                  "value":"Test vulnerability"
                                },
                                {
                                  "name":"internal:osv:ecosystem",
                                  "value":"maven"
                                }
                              ]
                            }
                          ]
                        }
                        """);

        dataSource.markProcessed(bom);
        verify(watermarkManagerMock).maybeAdvance(eq(ecosystem), any());

        dataSource.close();
        verify(watermarkManagerMock).maybeCommit(any());
    }

    @Test
    void shouldPercentEncodeSpacesInEcosystemNameForFullArchive(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var zipBytes = new ByteArrayOutputStream();
        try (var zos = new ZipOutputStream(zipBytes)) {
            zos.putNextEntry(new ZipEntry("osv-advisory.json"));
            zos.write(/* language=JSON */ """
                    {
                      "id": "OSV-1",
                      "summary": "test",
                      "affected": [],
                      "modified": "2024-01-01T00:00:00Z"
                    }
                    """.getBytes());
            zos.closeEntry();
        }
        stubFor(get(urlEqualTo("/Red%20Hat/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/zip")
                        .withBody(zipBytes.toByteArray())));

        try (var dataSource = new OsvVulnDataSource(
                null,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("Red Hat"),
                HttpClient.newHttpClient(),
                false)) {
            assertTrue(dataSource.hasNext());
            assertThat(dataSource.next().getVulnerabilitiesList().getFirst().getId()).isEqualTo("OSV-1");
        }

        verify(getRequestedFor(urlEqualTo("/Red%20Hat/all.zip")));
        verify(0, getRequestedFor(urlPathMatching(".*/Red\\+Hat/.*")));
    }

    @Test
    void shouldSkipDirectoryAndNonJsonEntriesInFullArchive(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            zos.putNextEntry(new ZipEntry("nested/"));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("README.txt"));
            zos.write("not an advisory".getBytes());
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("nested/OSV-1.json"));
            zos.write(/* language=JSON */ """
                    {"id":"OSV-1","summary":"first","affected":[],"modified":"2024-01-01T00:00:00Z"}
                    """.getBytes());
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("OSV-2.json"));
            zos.write(/* language=JSON */ """
                    {"id":"OSV-2","summary":"second","affected":[],"modified":"2024-01-02T00:00:00Z"}
                    """.getBytes());
            zos.closeEntry();
        }
        stubFor(get(urlEqualTo("/maven/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/zip")
                        .withBody(zipBytes.toByteArray())));

        final var ids = new ArrayList<String>();
        try (var dataSource = new OsvVulnDataSource(
                null,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            while (dataSource.hasNext()) {
                ids.add(dataSource.next().getVulnerabilitiesList().getFirst().getId());
            }
        }

        assertThat(ids).containsExactlyInAnyOrder("OSV-1", "OSV-2");
    }

    @Test
    void nullWatermarkManagerPerformsFullDownload(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = /* language=JSON */ """
                    {
                      "id": "OSV-2024-001",
                      "summary": "Test",
                      "affected": [],
                      "modified": "2024-01-01T00:00:00Z"
                    }
                    """;
            zos.write(advisoryJson.getBytes());
            zos.closeEntry();
        }
        stubFor(get(urlEqualTo("/maven/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(zipBytes.toByteArray())
                        .withHeader("Content-Type", "application/zip")));

        try (var dataSource = new OsvVulnDataSource(
                null,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            assertTrue(dataSource.hasNext());
            Bom first = dataSource.next();
            assertThat(first.getVulnerabilitiesList()).hasSize(1);
            dataSource.markProcessed(first);
            assertThat(dataSource.hasNext()).isFalse();
        }

        verify(getRequestedFor(urlEqualTo("/maven/all.zip")));
        verify(0, getRequestedFor(urlPathMatching(".*/modified_id\\.csv")));
    }

    @Test
    void watermarkManagerReturnsNullPerformsFullDownload(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        when(watermarkManagerMock.getWatermark("maven")).thenReturn(null);
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBytes)) {
            ZipEntry entry = new ZipEntry("osv-advisory.json");
            zos.putNextEntry(entry);
            String advisoryJson = /* language=JSON */ """
                    {
                      "id": "OSV-2024-002",
                      "summary": "Test",
                      "affected": [],
                      "modified": "2024-01-02T00:00:00Z"
                    }
                    """;
            zos.write(advisoryJson.getBytes());
            zos.closeEntry();
        }
        stubFor(get(urlEqualTo("/maven/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(zipBytes.toByteArray())
                        .withHeader("Content-Type", "application/zip")));

        try (var dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            assertTrue(dataSource.hasNext());
            Bom first = dataSource.next();
            assertThat(first.getVulnerabilitiesList().get(0).getId()).isEqualTo("OSV-2024-002");
            dataSource.markProcessed(first);
            assertThat(dataSource.hasNext()).isFalse();
        }

        verify(getRequestedFor(urlEqualTo("/maven/all.zip")));
        verify(0, getRequestedFor(urlPathMatching(".*/modified_id\\.csv")));
    }

    @Test
    void watermarkManagerReturnsInstantPerformsIncrementalDownload(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        when(watermarkManagerMock.getWatermark("maven")).thenReturn(Instant.parse("2024-01-01T00:00:00Z"));
        String csvBody = "2025-01-01T00:00:00Z,OSV-123\n";
        stubFor(get(urlEqualTo("/maven/modified_id.csv"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/csv")
                        .withBody(csvBody)));
        String advisoryJson = /* language=JSON */ """
                {
                  "id": "OSV-123",
                  "summary": "Incremental advisory",
                  "affected": [],
                  "modified": "2025-01-01T00:00:00Z"
                }
                """;
        stubFor(get(urlEqualTo("/maven/OSV-123.json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(advisoryJson)));

        try (var dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            assertTrue(dataSource.hasNext());
            Bom first = dataSource.next();
            assertThat(first.getVulnerabilitiesList()).hasSize(1);
            assertThat(first.getVulnerabilitiesList().getFirst().getId()).isEqualTo("OSV-123");
            dataSource.markProcessed(first);
            assertThat(dataSource.hasNext()).isFalse();
        }

        verify(getRequestedFor(urlEqualTo("/maven/modified_id.csv")));
        verify(getRequestedFor(urlEqualTo("/maven/OSV-123.json")));
        verify(0, getRequestedFor(urlEqualTo("/maven/all.zip")));
    }

    @Test
    void shouldDownloadIncrementalAdvisoriesLazily(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        when(watermarkManagerMock.getWatermark("maven")).thenReturn(Instant.parse("2024-01-01T00:00:00Z"));
        String csvBody = """
                2025-01-02T00:00:00Z,OSV-2
                2025-01-01T00:00:00Z,OSV-1
                """;
        stubFor(get(urlEqualTo("/maven/modified_id.csv"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/csv")
                        .withBody(csvBody)));
        for (final String id : List.of("OSV-1", "OSV-2")) {
            stubFor(get(urlEqualTo("/maven/" + id + ".json"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(/* language=JSON */ """
                                    {"id":"%s","summary":"s","affected":[],"modified":"2025-01-01T00:00:00Z"}
                                    """.formatted(id))));
        }

        try (var dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            assertThat(dataSource.hasNext()).isTrue();
            verify(1, getRequestedFor(urlPathMatching("/maven/OSV-.*\\.json")));

            dataSource.next();
            verify(1, getRequestedFor(urlPathMatching("/maven/OSV-.*\\.json")));

            assertThat(dataSource.hasNext()).isTrue();
            verify(2, getRequestedFor(urlPathMatching("/maven/OSV-.*\\.json")));

            dataSource.next();
            assertThat(dataSource.hasNext()).isFalse();
        }
    }

    @Test
    void shouldFallBackToFullDownloadWhenIncrementalThresholdExceeded(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        when(watermarkManagerMock.getWatermark("maven")).thenReturn(Instant.parse("2024-01-01T00:00:00Z"));

        final var csvBody = new StringBuilder();
        for (int i = 0; i < 251; i++) {
            csvBody.append("2025-01-01T00:00:00Z,OSV-%d\n".formatted(i));
        }
        stubFor(get(urlEqualTo("/maven/modified_id.csv"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/csv")
                        .withBody(csvBody.toString())));

        var zipBytes = new ByteArrayOutputStream();
        try (var zos = new ZipOutputStream(zipBytes)) {
            zos.putNextEntry(new ZipEntry("osv-advisory.json"));
            zos.write(/* language=JSON */ """
                    {
                      "id": "OSV-789",
                      "summary": "Test vulnerability",
                      "affected": [],
                      "modified": "2025-01-01T00:00:00Z"
                    }
                    """.getBytes());
            zos.closeEntry();
        }
        stubFor(get(urlEqualTo("/maven/all.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/zip")
                        .withBody(zipBytes.toByteArray())));

        try (var dataSource = new OsvVulnDataSource(
                watermarkManagerMock,
                objectMapper,
                wmRuntimeInfo.getHttpBaseUrl(),
                List.of("maven"),
                HttpClient.newHttpClient(),
                false)) {
            assertTrue(dataSource.hasNext());
            Bom first = dataSource.next();
            assertThat(first.getVulnerabilitiesList().getFirst().getId()).isEqualTo("OSV-789");
            assertThat(dataSource.hasNext()).isFalse();
        }

        verify(getRequestedFor(urlEqualTo("/maven/modified_id.csv")));
        verify(getRequestedFor(urlEqualTo("/maven/all.zip")));
        verify(0, getRequestedFor(urlPathMatching("/maven/OSV-.*\\.json")));
    }

}