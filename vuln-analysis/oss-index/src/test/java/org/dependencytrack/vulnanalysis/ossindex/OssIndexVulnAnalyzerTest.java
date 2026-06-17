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
package org.dependencytrack.vulnanalysis.ossindex;

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
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class OssIndexVulnAnalyzerTest {

    private CacheManager cacheManager;
    private OssIndexVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        analyzer = createAnalyzer(wmRuntimeInfo, "foo@example.com", "710bcaff-790b-494d-872a-eb97cdc676ef");
    }

    private VulnAnalyzer createAnalyzer(
            WireMockRuntimeInfo wmRuntimeInfo,
            String username,
            String apiToken) {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        analyzerFactory = new OssIndexVulnAnalyzerFactory();

        final var config = new OssIndexVulnAnalyzerConfigV1()
                .withEnabled(true)
                .withAliasSyncEnabled(true)
                .withApiUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                .withApiToken(apiToken);
        if (username != null) {
            config.withUsername(username);
        }

        final var configRegistry = new MockConfigRegistry(
                Map.of("allow-local-connections", "true"),
                analyzerFactory.runtimeConfigSpec(),
                RuntimeConfigMapper.getInstance(),
                config);

        analyzerFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        return analyzerFactory.create();
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
        stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("no-vulns-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1")
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
        stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("vulns-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "CVE-2020-36518",
                      "source": {
                        "name": "NVD"
                      },
                      "ratings": [
                        {
                          "source": {
                            "name": "OSSINDEX"
                          },
                          "score": 7.5,
                          "method": "SCORE_METHOD_CVSSV31",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                        }
                      ],
                      "cwes": [
                        787
                      ],
                      "description": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.\\n\\nSonatype's research suggests that this CVE's details differ from those defined at NVD. See https://ossindex.sonatype.org/vulnerability/CVE-2020-36518 for details",
                      "advisories": [
                        {
                          "url": "https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0"
                        },
                        {
                          "url": "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518"
                        },
                        {
                          "url": "https://github.com/FasterXML/jackson-databind/issues/2816"
                        }
                      ],
                      "affects": [
                        {
                          "ref": "1"
                        }
                      ],
                      "properties": [
                        {
                          "name":"dependency-track:vuln:title",
                          "value": "[CVE-2020-36518] CWE-787: Out-of-bounds Write"
                        },
                        {
                          "name": "dependency-track:vuln:reference-url",
                          "value": "https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0"
                        }
                      ]
                    }
                  ]
                }
                """);

        final var secondBom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?foo=bar#baz")
                                .build())
                .build();

        final Bom secondVdr = analyzer.analyze(secondBom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
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
                                .setPurl("pkg:generic/acme-artefact@1.2.3")
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
    void shouldBatchRequestsWithUpTo128Purls() throws Exception {
        stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse()
                        .withStatus(200)
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

        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(matchingJsonPath("$[?(@.coordinates.size() == 128)]")));
        verify(1, postRequestedFor(anyUrl())
                .withRequestBody(matchingJsonPath("$[?(@.coordinates.size() == 22)]")));
    }

    @Test
    void shouldUseBearerAuthHeaderWhenUsernameIsAbsent(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        analyzerFactory.close();
        cacheManager.close();
        analyzer = createAnalyzer(wmRuntimeInfo, null, "sonatype_pat_test");

        stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                .withHeader("Authorization", equalTo("Bearer sonatype_pat_test")));
    }

}