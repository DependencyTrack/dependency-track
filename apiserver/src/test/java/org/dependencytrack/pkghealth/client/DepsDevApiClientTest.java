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
package org.dependencytrack.pkghealth.client;

import com.github.packageurl.PackageURL;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.common.Mappers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class DepsDevApiClientTest {

    @RegisterExtension
    static final WireMockExtension wm = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .configureStaticDsl(true)
            .build();

    private DepsDevApiClient client;

    @BeforeEach
    void beforeEach() {
        client = new DepsDevApiClient(HttpClient.newHttpClient(), Mappers.jsonMapper(), wm.baseUrl());
    }

    @Test
    void shouldBuildPackagePageUrl() {
        final var pageClient = new DepsDevApiClient(
                HttpClient.newHttpClient(), Mappers.jsonMapper(), "https://api.deps.dev", "https://deps.dev");

        assertThat(pageClient.packagePageUrl("NPM", "lodash")).isEqualTo("https://deps.dev/npm/lodash");
        assertThat(pageClient.packagePageUrl("MAVEN", "org.apache.commons:commons-lang3"))
                .isEqualTo("https://deps.dev/maven/org.apache.commons%3Acommons-lang3");
        assertThat(pageClient.packagePageUrl("GO", "github.com/gin-gonic/gin"))
                .isEqualTo("https://deps.dev/go/github.com%2Fgin-gonic%2Fgin");
        assertThat(pageClient.packagePageUrl(null, "lodash")).isNull();
    }

    @Test
    void shouldFetchDefaultVersion() throws Exception {
        stubPackageResponse("""
                {
                  "versions": [
                    {
                      "versionKey": {
                        "version": "4.17.20"
                      },
                      "isDefault": false
                    },
                    {
                      "versionKey": {
                        "version": "4.17.21"
                      },
                      "isDefault": true
                    }
                  ]
                }
                """);

        final var result = client.fetchLatestVersion("NPM", "lodash");

        assertThat(result).contains("4.17.21");
    }

    @Test
    void shouldReturnEmptyWhenNoDefaultVersionExists() throws Exception {
        stubPackageResponse("""
                {
                  "versions": [
                    {
                      "versionKey": {
                        "version": "4.17.20"
                      },
                      "isDefault": false
                    }
                  ]
                }
                """);

        final var result = client.fetchLatestVersion("NPM", "lodash");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenPackageDoesNotExist() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse().withStatus(404)));

        final var result = client.fetchLatestVersion("NPM", "lodash");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldFetchDependents() throws Exception {
        stubFor(get(urlPathEqualTo("/v3alpha/systems/NPM/packages/lodash" + "/versions/4.17.21:dependents"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "dependentCount": 1234
                            }
                            """)));

        final var result = client.fetchDependents("NPM", "lodash", "4.17.21");

        assertThat(result).contains(1234L);
    }

    @Test
    void shouldReturnEmptyWhenDependentCountIsMissing() throws Exception {
        stubFor(get(urlPathEqualTo("/v3alpha/systems/NPM/packages/lodash" + "/versions/4.17.21:dependents"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        final var result = client.fetchDependents("NPM", "lodash", "4.17.21");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldFetchSourceRepository() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash" + "/versions/4.17.21"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "relatedProjects": [
                                {
                                  "projectKey": {
                                    "id": "github.com/lodash/lodash"
                                  },
                                  "relationType": "SOURCE_REPO"
                                }
                              ]
                            }
                            """)));

        final var result = client.fetchSourceRepository("NPM", "lodash", "4.17.21");

        assertThat(result).contains("github.com/lodash/lodash");
    }

    @Test
    void shouldIgnoreNonSourceRepositories() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash" + "/versions/4.17.21"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "relatedProjects": [
                                {
                                  "projectKey": {
                                    "id": "github.com/lodash/lodash"
                                  },
                                  "relationType": "ISSUE_TRACKER"
                                }
                              ]
                            }
                            """)));

        final var result = client.fetchSourceRepository("NPM", "lodash", "4.17.21");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldFetchProjectAndScorecardMetadata() throws Exception {
        stubFor(get(urlPathEqualTo("/_/project/GITHUB/lodash%2Flodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "project": {
                                "observedAt": 1658223503
                              }
                            }
                            """)));
        stubFor(get(urlPathEqualTo("/v3/projects/github.com%2Flodash%2Flodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "starsCount": 61234,
                              "forksCount": 7021,
                              "openIssuesCount": 128,
                              "scorecard": {
                                "overallScore": 8.7,
                                "date": "2026-09-20T12:30:00Z",
                                "scorecard": {
                                  "version": "v5.0.0"
                                },
                                "checks": [
                                  {
                                    "name": "Maintained",
                                    "score": 10,
                                    "reason": "30 commit(s) found",
                                    "details": [
                                      "Repository was active"
                                    ],
                                    "documentation": {
                                      "shortDescription":
                                          "Determines whether the project is maintained",
                                      "url":
                                          "https://github.com/ossf/scorecard/blob/main/docs/checks.md"
                                    }
                                  }
                                ]
                              }
                            }
                            """)));

        final var purl = new PackageURL("pkg:npm/lodash");

        final var result = client.fetchProjectMetadata(purl, "github.com/lodash/lodash");

        assertThat(result).isPresent();

        final var metadata = result.orElseThrow();

        assertThat(metadata.getStars()).isEqualTo(61234L);
        assertThat(metadata.getForks()).isEqualTo(7021L);
        assertThat(metadata.getOpenIssues()).isEqualTo(128L);
        assertThat(metadata.getProjectMetadataObservedAt()).isEqualTo(Instant.ofEpochSecond(1658223503));
        assertThat(metadata.getScorecardScore()).isEqualTo(8.7f);
        assertThat(metadata.getScorecardReferenceVersion()).isEqualTo("v5.0.0");
        assertThat(metadata.getScorecardTimestamp()).isEqualTo(Instant.parse("2026-09-20T12:30:00Z"));

        assertThat(metadata.getScorecardChecks()).singleElement().satisfies(check -> {
            assertThat(check.purl()).isEqualTo(purl);
            assertThat(check.name()).isEqualTo("Maintained");
            assertThat(check.score()).isEqualTo(10.0f);
            assertThat(check.reason()).isEqualTo("30 commit(s) found");
            assertThat(check.details()).containsExactly("Repository was active");
            assertThat(check.description()).isEqualTo("Determines whether the project is maintained");
            assertThat(check.documentationUrl())
                    .isEqualTo("https://github.com/ossf/scorecard/blob/main/docs/checks.md");
        });
    }

    @Test
    void shouldFetchProjectMetadataWithoutScorecard() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/projects/github.com%2Flodash%2Flodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "starsCount": 61234,
                              "forksCount": 7021,
                              "openIssuesCount": 128
                            }
                            """)));

        final var purl = new PackageURL("pkg:npm/lodash");

        final var result = client.fetchProjectMetadata(purl, "github.com/lodash/lodash");

        assertThat(result).isPresent();

        final var metadata = result.orElseThrow();

        assertThat(metadata.getStars()).isEqualTo(61234L);
        assertThat(metadata.getForks()).isEqualTo(7021L);
        assertThat(metadata.getOpenIssues()).isEqualTo(128L);
        assertThat(metadata.getScorecardScore()).isNull();
        assertThat(metadata.getScorecardReferenceVersion()).isNull();
        assertThat(metadata.getScorecardTimestamp()).isNull();
        assertThat(metadata.getScorecardChecks()).isEmpty();
    }

    @Test
    void shouldKeepProjectMetadataWhenObservedAtLookupFails() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/projects/github.com%2Flodash%2Flodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "starsCount": 10,
                              "forksCount": 2
                            }
                            """)));
        stubFor(get(urlPathEqualTo("/_/project/GITHUB/lodash%2Flodash"))
                .willReturn(aResponse().withStatus(500)));

        final var result = client.fetchProjectMetadata(new PackageURL("pkg:npm/lodash"), "github.com/lodash/lodash");

        assertThat(result).isPresent();
        assertThat(result.orElseThrow().getStars()).isEqualTo(10L);
        assertThat(result.orElseThrow().getProjectMetadataObservedAt()).isNull();
    }

    @Test
    void shouldFetchProjectMetadataObservedAt() throws Exception {
        stubFor(get(urlPathEqualTo("/_/project/GITHUB/substack%2Fnode-wordwrap"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "project": {
                                "observedAt": 1658223503,
                                "stars": 142,
                                "forks": 27
                              }
                            }
                            """)));

        assertThat(client.fetchProjectMetadataObservedAt("github.com/substack/node-wordwrap"))
                .contains(Instant.ofEpochSecond(1658223503));
        assertThat(client.fetchProjectMetadataObservedAt("GitHub.com/substack/node-wordwrap"))
                .contains(Instant.ofEpochSecond(1658223503));
    }

    @Test
    void shouldLeaveProjectMetadataObservedAtAbsentWhenMissing() throws Exception {
        stubFor(get(urlPathEqualTo("/_/project/GITHUB/acme%2Fexample"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "project": {
                                "stars": 1
                              }
                            }
                            """)));

        assertThat(client.fetchProjectMetadataObservedAt("github.com/acme/example"))
                .isEmpty();
        assertThat(client.fetchProjectMetadataObservedAt("gitlab.com/acme/example"))
                .isEmpty();
    }

    @Test
    void shouldThrowOnServerError() {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse().withStatus(500)));

        assertThatExceptionOfType(IOException.class).isThrownBy(() -> client.fetchLatestVersion("NPM", "lodash"));
    }

    @Test
    void shouldThrowOnMalformedJson() {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{invalid-json")));

        assertThatExceptionOfType(IOException.class).isThrownBy(() -> client.fetchLatestVersion("NPM", "lodash"));
    }

    @Test
    void shouldTreatRetryAfterAsRateLimit() {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse().withStatus(429).withHeader("retry-after", "30")));

        final Instant before = Instant.now();
        assertThatExceptionOfType(ApiRateLimitException.class)
                .isThrownBy(() -> client.fetchLatestVersion("NPM", "lodash"))
                .satisfies(e -> assertThat(e.resetAt())
                        .isBetween(before.plusSeconds(30), Instant.now().plusSeconds(30)));
    }

    @Test
    void shouldWaitOneMinuteOn429WithoutRateLimitHeaders() {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse().withStatus(429)));

        final Instant before = Instant.now();
        assertThatExceptionOfType(ApiRateLimitException.class)
                .isThrownBy(() -> client.fetchLatestVersion("NPM", "lodash"))
                .satisfies(e -> assertThat(e.resetAt())
                        .isBetween(before.plusSeconds(60), Instant.now().plusSeconds(60)));
    }

    @Test
    void shouldNotTreatForbiddenWithoutRateLimitHeadersAsRateLimit() {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse().withStatus(403)));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> client.fetchLatestVersion("NPM", "lodash"))
                .isNotInstanceOf(ApiRateLimitException.class);
    }

    private static void stubPackageResponse(final String responseBody) {
        stubFor(get(urlPathEqualTo("/v3/systems/NPM/packages/lodash"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(responseBody)));
    }
}
