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
package org.dependencytrack.vulnanalysis.checkmarx;

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
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class CheckmarxVulnAnalyzerTest {

    private CacheManager cacheManager;
    private CheckmarxVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        analyzerFactory = new CheckmarxVulnAnalyzerFactory();

        final var configRegistry = new MockConfigRegistry(
                analyzerFactory.runtimeConfigSpec(),
                new CheckmarxVulnAnalyzerConfigV1()
                        .withEnabled(true)
                        .withAliasSyncEnabled(true)
                        .withApiBaseUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                        .withOrgId("test-org-id")
                        .withAuthApiBaseUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                        .withRefreshToken("test-refresh-token"));

        analyzerFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        // Stub auth token endpoint used by CheckmarxAccessTokenManager
        stubFor(post(urlPathMatching("/auth/realms/test-org-id/protocol/openid-connect/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                             {   "access_token": "test-access-token",
                                 "expires_in": 3600,
                                 "refresh_token": "test-refresh-token",
                                 "refresh_expires_in": 3600
                             }""")));

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
        stubFor(post(urlPathEqualTo("/api/sca/packages/vulnerabilities"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("chx-no-issues-response.json")));

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

        verify(1, postRequestedFor(anyUrl())
                .withHeader("Authorization", equalTo("Bearer test-access-token")));
    }

    @Test
    void shouldAnalyzeAndCacheWithVulns() throws Exception {
        stubFor(post(urlPathEqualTo("/api/sca/packages/vulnerabilities"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("chx-response-with-vulns.json")));

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
                  "vulnerabilities" : [ {
                    "id" : "cx987654-32g1",
                    "source" : {
                      "name" : "CX"
                    },
                    "references" : [ {
                      "id" : "CVE-2021-25649",
                      "source" : {
                        "name" : "NVD"
                      }
                    } ],
                    "ratings" : [ {
                      "score" : 5.0,
                      "severity" : "SEVERITY_MEDIUM",
                      "method" : "SCORE_METHOD_CVSSV4",
                      "vector" : "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
                    } ],
                    "cwes" : [ 501 ],
                    "description" : "A vulnerability was found in jackson-databind.",
                    "recommendation" : "Smallest package upgrade that resolves the identified risks in the current package version: 2.13.4\\nLatest version of the package: 2.13.4",
                    "advisories" : [ {
                      "url" : "https://nvd.nist.gov/vuln/detail/CVE-2021-25649"
                    }, {
                      "url" : "https://spring.io/security/CVE-2021-25649"
                    } ],
                    "created" : "2020-12-15T00:00:00Z",
                    "published" : "2021-10-15T00:00:00Z",
                    "updated" : "2021-12-15T00:00:00Z",
                    "affects" : [ {
                      "ref" : "1"
                    } ]
                  }, {
                    "id" : "cx123456-78c9",
                    "source" : {
                      "name" : "CX"
                    },
                    "references" : [ {
                      "id" : "CVE-2020-25649",
                      "source" : {
                        "name" : "NVD"
                      }
                    } ],
                    "ratings" : [ {
                      "score" : 7.5,
                      "severity" : "SEVERITY_HIGH",
                      "method" : "SCORE_METHOD_CVSSV3",
                      "vector" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    } ],
                    "cwes" : [ 502 ],
                    "description" : "A vulnerability was found in jackson-databind.",
                    "recommendation" : "Smallest package upgrade that resolves the identified risks in the current package version: 2.13.4\\nLatest version of the package: 2.13.4",
                    "advisories" : [ {
                      "url" : "https://nvd.nist.gov/vuln/detail/CVE-2020-25649"
                    }, {
                      "url" : "https://spring.io/security/CVE-2020-25649"
                    } ],
                    "created" : "2020-12-15T00:00:00Z",
                    "published" : "2021-10-15T00:00:00Z",
                    "updated" : "2021-12-15T00:00:00Z",
                    "affects" : [ {
                      "ref" : "1"
                    } ]
                  } ]
                }
                """);

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl())
                .withHeader("Authorization", equalTo("Bearer test-access-token")));
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
    void shouldNotAnalyzeComponentWithUnsupportedPackageType() throws Exception {
        stubFor(post(urlPathEqualTo("/api/sca/packages/vulnerabilities"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("chx-non-okay-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:rpm/acme-artefact@1.2.3")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());
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
        stubFor(post(urlPathEqualTo("/api/sca/packages/vulnerabilities"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("[]")));

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

        verify(2, postRequestedFor(urlPathEqualTo("/api/sca/packages/vulnerabilities")));
    }
}
