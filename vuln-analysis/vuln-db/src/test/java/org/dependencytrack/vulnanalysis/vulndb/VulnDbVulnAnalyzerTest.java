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
package org.dependencytrack.vulnanalysis.vulndb;

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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class VulnDbVulnAnalyzerTest {

    private CacheManager cacheManager;
    private VulnDbVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        analyzerFactory = new VulnDbVulnAnalyzerFactory();

        final var configRegistry = new MockConfigRegistry(
                analyzerFactory.runtimeConfigSpec(),
                new VulnDbVulnAnalyzerConfigV1()
                        .withEnabled(true)
                        .withAliasSyncEnabled(true)
                        .withApiUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                        .withOauth2ClientId("test-client-id")
                        .withOauth2ClientSecret("test-client-secret"));

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
    void shouldAnalyzeAndCacheWithVulns() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("vulndb-response-with-vulns.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("example-lib")
                                .setCpe("cpe:2.3:a:example:lib:1.0:*:*:*:*:*:*:*")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "123456",
                      "source": {
                        "name": "VULNDB"
                      },
                      "ratings": [
                        {
                          "source": { "name": "VULNDB" },
                          "score": 5.0,
                          "method": "SCORE_METHOD_CVSSV2",
                          "vector": "(AV:N/AC:L/Au:N/C:P/I:N/A:N)"
                        },
                        {
                          "source": { "name": "VULNDB" },
                          "score": 7.5,
                          "method": "SCORE_METHOD_CVSSV3",
                          "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        }
                      ],
                      "cwes": [120],
                      "description": "A vulnerability was found in Example Library.\\n\\nBuffer overflow in parsing module.\\n\\nUpgrade to version 2.0 or later.",
                      "advisories": [
                        { "url": "https://example.com/advisory/123" }
                      ],
                      "references": [
                        { "id": "CVE-2023-12345", "source": { "name": "NVD" } }
                      ],
                      "affects": [
                        { "ref": "1" }
                      ],
                      "properties": [
                        { "name": "dependency-track:vuln:title", "value": "Test Vulnerability in Example Library" },
                        { "name": "dependency-track:vuln:credits", "value": "John Doe" }
                      ]
                    }
                  ]
                }
                """);

        // Second call should use cache.
        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, getRequestedFor(anyUrl())
                .withHeader("Authorization", equalTo("Bearer test-token")));
    }

    @Test
    void shouldAnalyzeAndCacheWithNoVulns() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("vulndb-response-no-vulns.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("safe-lib")
                                .setCpe("cpe:2.3:a:example:safe-lib:1.0:*:*:*:*:*:*:*")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, getRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeComponentWithoutBomRef() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setName("example-lib")
                                .setCpe("cpe:2.3:a:example:lib:1.0:*:*:*:*:*:*:*")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, getRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeComponentWithoutCpe() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("example-lib")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, getRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeInternalComponents() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("internal-lib")
                                .setCpe("cpe:2.3:a:example:internal:1.0:*:*:*:*:*:*:*")
                                .addProperties(
                                        Property.newBuilder()
                                                .setName("dependencytrack:internal:is-internal-component")
                                                .setValue("does-not-matter")
                                                .build())
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, getRequestedFor(anyUrl()));
    }

    @Test
    void shouldHandlePagination() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withQueryParam("page", equalTo("1"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("vulndb-response-with-vulns-page1.json")));

        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withQueryParam("page", equalTo("2"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("vulndb-response-with-vulns-page2.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("example-lib")
                                .setCpe("cpe:2.3:a:example:lib:1.0:*:*:*:*:*:*:*")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesCount()).isEqualTo(2);

        verify(1, getRequestedFor(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withQueryParam("page", equalTo("1")));
        verify(1, getRequestedFor(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withQueryParam("page", equalTo("2")));
    }

    @Test
    void shouldAnalyzeMultipleCpes() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("vulndb-response-no-vulns.json")));

        final var bomBuilder = Bom.newBuilder();
        for (int i = 0; i < 10; i++) {
            bomBuilder.addComponents(
                    Component.newBuilder()
                            .setBomRef(String.valueOf(i))
                            .setName("lib-" + i)
                            .setCpe("cpe:2.3:a:example:lib-" + i + ":1.0:*:*:*:*:*:*:*")
                            .build());
        }

        final Bom vdr = analyzer.analyze(bomBuilder.build());
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(10, getRequestedFor(anyUrl()));
    }

}
