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
package org.dependencytrack.vulnanalysis.snyk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class SnykVulnAnalyzerChecksumMatchingTest {

    private static final String CHECKSUM_PURL =
            "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1:40fd4d696c55793e996d1ff3c475833f836c2498";
    private static final String PARTIAL_CHECKSUM_PURL =
            "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String NONE_CHECKSUM_PURL =
            "pkg:maven/org.example/unknown@1.0.0?checksum=sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private CacheManager cacheManager;
    private SnykVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        analyzerFactory = new SnykVulnAnalyzerFactory();

        final var configRegistry = new MockConfigRegistry(
                analyzerFactory.runtimeConfigSpec(),
                new SnykVulnAnalyzerConfigV1()
                        .withEnabled(true)
                        .withAliasSyncEnabled(true)
                        .withChecksumMatchingEnabled(true)
                        .withApiBaseUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                        .withOrgId("test-org-id")
                        .withApiToken("test-api-token"));

        analyzerFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        analyzer = analyzerFactory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (analyzerFactory != null) {
            analyzerFactory.close();
        }
        if (cacheManager != null) {
            cacheManager.close();
        }
    }

    @Test
    void shouldSendChecksumQualifiedMavenPurlAndCacheFullMatchWithNoIssues() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-checksum-full-match-no-issues.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jboss-logging")
                        .setPurl(CHECKSUM_PURL)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).isEmpty();

        // Second analysis should hit cache — no additional HTTP.
        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(containing("checksum")));
    }

    @Test
    void shouldAttachIssuesOnFullMatchAndSkipHttpOnCacheHit() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-checksum-full-match-with-issues.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jboss-logging")
                        .setPurl(CHECKSUM_PURL)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesCount()).isEqualTo(1);
        assertThat(vdr.getVulnerabilities(0).getId()).isEqualTo("SNYK-JAVA-ORGJBOSSLOGGING-0000001");
        assertThat(vdr.getVulnerabilities(0).getAffects(0).getRef()).isEqualTo("1");

        final Bom cachedVdr = analyzer.analyze(bom);
        assertThat(cachedVdr.getVulnerabilitiesCount()).isEqualTo(1);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldSkipFindingsButCachePartialMatch() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-checksum-partial-match.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jboss-logging")
                        .setPurl(PARTIAL_CHECKSUM_PURL)
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();
        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldSkipFindingsButCacheNoneMatch() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-checksum-none-match.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("unknown")
                        .setPurl(NONE_CHECKSUM_PURL)
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();
        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldUseCoordinatesOnlyForMavenWithoutChecksum() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-no-issues-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jackson-databind")
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(equalToJson("""
                        {
                          "data": {
                            "attributes": {
                              "purls": [
                                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4"
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Test
    void shouldUseCoordinatesOnlyForNonMavenWithChecksumQualifier() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBody("{\"data\":[]}")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("lodash")
                        .setPurl("pkg:npm/lodash@4.17.21?checksum=sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(containing("pkg:npm/lodash@4.17.21"))
                .withRequestBody(containing("\"purls\"")));
        // Request must not include the checksum qualifier for non-Maven.
        verify(0, postRequestedFor(anyUrl())
                .withRequestBody(containing("checksum=")));
    }

    @Test
    void shouldNotCacheWhenMetaErrorsPresentForChecksumPurl() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-meta-errors.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jboss-logging")
                        .setPurl(CHECKSUM_PURL)
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();
        // No usable meta.packages → not cached → second call hits HTTP again.
        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(2, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldStripChecksumWhenFlagDisabled(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        analyzerFactory.close();
        analyzerFactory = new SnykVulnAnalyzerFactory();

        final var configRegistry = new MockConfigRegistry(
                analyzerFactory.runtimeConfigSpec(),
                new SnykVulnAnalyzerConfigV1()
                        .withEnabled(true)
                        .withAliasSyncEnabled(true)
                        .withChecksumMatchingEnabled(false)
                        .withApiBaseUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                        .withOrgId("test-org-id")
                        .withApiToken("test-api-token"));

        analyzerFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient()));
        analyzer = analyzerFactory.create();

        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-no-issues-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jboss-logging")
                        .setPurl(CHECKSUM_PURL)
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(equalToJson("""
                        {
                          "data": {
                            "attributes": {
                              "purls": [
                                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.final"
                              ]
                            }
                          }
                        }
                        """)));
        verify(0, postRequestedFor(anyUrl())
                .withRequestBody(containing("checksum=")));
    }

    @Test
    void shouldAnalyzeMixedChecksumAndCoordinatesPurlsInSameBatch() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-batch-mixed-purls.json")));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("checksum-comp")
                        .setName("jboss-logging")
                        .setPurl(CHECKSUM_PURL)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("coords-comp")
                        .setName("jackson-databind")
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).hasSize(2);
        assertThat(vdr.getVulnerabilitiesList())
                .anySatisfy(v -> {
                    assertThat(v.getId()).isEqualTo("SNYK-JAVA-ORGJBOSSLOGGING-0000001");
                    assertThat(v.getAffects(0).getRef()).isEqualTo("checksum-comp");
                })
                .anySatisfy(v -> {
                    assertThat(v.getId()).isEqualTo("SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426");
                    assertThat(v.getAffects(0).getRef()).isEqualTo("coords-comp");
                });

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(containing("checksum="))
                .withRequestBody(containing("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")));
    }

    @Test
    void shouldReadLegacyCachedIssueArrayAsFullMatch() throws Exception {
        final String coordsPurl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4";
        final byte[] legacyCacheValue = """
                [{
                  "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426",
                  "type": "issue",
                  "attributes": {
                    "title": "Denial of Service (DoS)",
                    "type": "package_vulnerability",
                    "created_at": "2022-10-02T09:41:44.046865Z",
                    "updated_at": "2022-11-28T01:11:01.289734Z",
                    "description": "Affected versions of this package are vulnerable to Denial of Service (DoS).",
                    "problems": [{"id": "CVE-2022-42003", "source": "CVE"}],
                    "coordinates": [{
                      "remedies": [{"type": "indeterminate", "description": "Upgrade"}],
                      "representations": [
                        {"resource_path": "[,2.13.4.2)"},
                        {"package": {
                          "name": "jackson-databind",
                          "version": "2.13.4",
                          "type": "maven",
                          "url": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4"
                        }}
                      ]
                    }],
                    "severities": [{
                      "source": "NVD",
                      "level": "high",
                      "score": 7.5,
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                    }],
                    "slots": {"publication_time": "2022-10-02T09:54:05Z", "references": []}
                  }
                }]
                """.getBytes(StandardCharsets.UTF_8);

        // Ensure Jackson can round-trip the payload (guards against accidental invalid fixture JSON).
        new ObjectMapper().readTree(legacyCacheValue);
        cacheManager.getCache("results").put(coordsPurl, legacyCacheValue);

        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse().withStatus(500)));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jackson-databind")
                        .setPurl(coordsPurl)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesCount()).isEqualTo(1);
        assertThat(vdr.getVulnerabilities(0).getId()).isEqualTo("SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426");

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldReadLegacyNullCacheEntryAsFullEmpty() throws Exception {
        final String coordsPurl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4";
        cacheManager.getCache("results").put(coordsPurl, null);

        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse().withStatus(500)));

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jackson-databind")
                        .setPurl(coordsPurl)
                        .build())
                .build();

        assertThat(analyzer.analyze(bom).getVulnerabilitiesList()).isEmpty();
        verify(0, postRequestedFor(anyUrl()));
    }

}
