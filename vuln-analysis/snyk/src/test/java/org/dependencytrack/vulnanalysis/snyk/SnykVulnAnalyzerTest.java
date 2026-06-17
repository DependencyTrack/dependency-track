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

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.protobuf.util.JsonFormat;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
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
import java.util.ArrayList;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class SnykVulnAnalyzerTest {

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
    void shouldAnalyzeAndCacheWithNoVulns() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-no-issues-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldAnalyzeAndCacheWithVulns() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-one-issue-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426",
                      "source": {
                        "name": "SNYK"
                      },
                      "ratings": [
                        {
                          "source": {
                            "name": "NVD"
                          },
                          "score": 7.5,
                          "method": "SCORE_METHOD_CVSSV31",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                        }
                      ],
                      "cwes": [
                        400
                      ],
                      "description": "Affected versions of this package are vulnerable to Denial of Service (DoS).",
                      "recommendation": "Upgrade the package version to 2.12.7.1,2.13.4.2 to fix this vulnerability",
                      "advisories": [
                        {
                          "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=51020"
                        },
                        {
                          "url": "https://github.com/FasterXML/jackson-databind/issues/3590"
                        }
                      ],
                      "created": "2022-10-02T09:41:44.046Z",
                      "updated": "2022-11-28T01:11:01.289Z",
                      "published": "2022-10-02T09:54:05Z",
                      "affects": [
                        {
                          "ref": "1"
                        }
                      ],
                      "properties": [
                        {
                          "name": "dependency-track:vuln:title",
                          "value": "Denial of Service (DoS)"
                        },
                        {
                          "name": "dependency-track:vuln:reference-url",
                          "value": "https://security.snyk.io/vuln/SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426"
                        }
                      ],
                      "references": [
                        {
                          "id": "CVE-2022-42003",
                          "source": {
                            "name": "NVD"
                          }
                        },
                        {
                          "id": "GHSA-jjjh-jjxp-wpff",
                          "source": {
                            "name": "GITHUB"
                          }
                        }
                      ]
                    }
                  ]
                }
                """);

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldAnalyzeWithMultipleVulns() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBodyFile("snyk-multiple-issues-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("woodstox-core")
                                .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesCount()).isEqualTo(2);
    }

    @Test
    void shouldNotAnalyzeComponentWithoutBomRef() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeComponentWithoutPurl() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeComponentsWithUnsupportedPurlType() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-artefact")
                                .setPurl("pkg:rpm/acme-artefact@1.2.3")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeInternalComponents() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .addProperties(
                                        Property.newBuilder()
                                                .setName("dependencytrack:internal:is-internal-component")
                                                .setValue("does-not-matter")
                                                .build())
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldBatchRequestsWithUpTo100Purls() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBody("{\"data\":[]}")));

        final var components = new ArrayList<Component>(150);
        for (int i = 0; i < 150; i++) {
            components.add(
                    Component.newBuilder()
                            .setBomRef(String.valueOf(i))
                            .setName("acme-lib")
                            .setPurl("pkg:maven/com.acme/acme-lib@1.0." + i)
                            .build());
        }

        final var bom = Bom.newBuilder()
                .addAllComponents(components)
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(2, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldHandleCaseInsensitivePurlCorrelation() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBody(/* language=JSON */ """
                                {
                                  "data": [
                                    {
                                      "id": "SNYK-JAVA-TEST-123",
                                      "type": "issue",
                                      "attributes": {
                                        "title": "Test Vuln",
                                        "description": "A test vulnerability",
                                        "problems": [],
                                        "coordinates": [
                                          {
                                            "representations": [
                                              {
                                                "resource_path": "[,1.0.0)"
                                              },
                                              {
                                                "package": {
                                                  "url": "pkg:maven/com.acme/acme-lib@1.0.0"
                                                }
                                              }
                                            ]
                                          }
                                        ],
                                        "severities": [
                                          {
                                            "source": "Snyk",
                                            "level": "high",
                                            "score": 7.5,
                                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                          }
                                        ],
                                        "slots": {}
                                      }
                                    }
                                  ]
                                }
                                """)));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.Acme/Acme-Lib@1.0.0")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesCount()).isEqualTo(1);
        assertThat(vdr.getVulnerabilities(0).getId()).isEqualTo("SNYK-JAVA-TEST-123");
        assertThat(vdr.getVulnerabilities(0).getAffects(0).getRef()).isEqualTo("1");
    }

    @Test
    void shouldSendCorrectHeaders() throws Exception {
        stubFor(post(urlPathEqualTo("/rest/orgs/test-org-id/packages/issues"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.api+json")
                        .withBody("{\"data\":[]}")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .build())
                .build();

        analyzer.analyze(bom);

        verify(1, postRequestedFor(anyUrl())
                .withHeader("Authorization", equalTo("token test-api-token"))
                .withHeader("Content-Type", equalTo("application/vnd.api+json"))
                .withHeader("Accept", equalTo("application/vnd.api+json")));
    }

}
