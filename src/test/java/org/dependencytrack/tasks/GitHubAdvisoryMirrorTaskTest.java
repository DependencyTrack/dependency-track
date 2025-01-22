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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.util.TimeValue;
import org.assertj.core.data.Offset;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;

public class GitHubAdvisoryMirrorTaskTest extends PersistenceCapableTest {

    private final ObjectMapper jsonMapper = new JsonMapper()
            .registerModule(new JavaTimeModule());

    @Before
    public void beforeEach() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getPropertyName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getDefaultPropertyValue(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getPropertyType(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyName(),
                "accessToken",
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyType(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getDescription());
    }

    @Test
    public void testProcessAdvisory() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getDescription());

        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "id": "GHSA-57j2-w4cx-62h2",
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "identifiers": [
                    {
                      "type": "CVE",
                      "value": "CVE-2020-36518"
                    }
                  ],
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:00Z",
                  "updatedAt": "2022-08-11T00:00:00Z",
                  "vulnerabilities": {
                    "edges": [
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": ">=2.13.0,<=2.13.2.0"
                        }
                      },
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": "<=2.12.6.0"
                        }
                      }
                    ]
                  }
                }
                """, SecurityAdvisory.class);

        final var task = new GitHubAdvisoryMirrorTask();
        final boolean createdOrUpdated = task.processAdvisory(advisory);
        assertThat(createdOrUpdated).isTrue();

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(vuln.getPublished()).isEqualToIgnoringHours("2022-03-12");
        assertThat(vuln.getUpdated()).isEqualToIgnoringHours("2022-08-11");

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vuln);
        assertThat(aliases).satisfiesExactly(
                alias -> {
                    assertThat(alias.getCveId()).isEqualTo("CVE-2020-36518");
                    assertThat(alias.getGhsaId()).isEqualTo("GHSA-57j2-w4cx-62h2");
                }
        );

        final List<VulnerableSoftware> vsList = vuln.getVulnerableSoftware();
        assertThat(vsList).hasSize(2);
    }

    @Test
    public void testProcessAdvisoryWithAliasSyncDisabled() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getPropertyName(),
                "false",
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED.getDescription());

        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "id": "GHSA-57j2-w4cx-62h2",
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "identifiers": [
                    {
                      "type": "CVE",
                      "value": "CVE-2020-36518"
                    }
                  ],
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:00Z",
                  "updatedAt": "2022-08-11T00:00:00Z",
                  "vulnerabilities": {
                    "edges": [
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": ">=2.13.0,<=2.13.2.0"
                        }
                      },
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": "<=2.12.6.0"
                        }
                      }
                    ]
                  }
                }
                """, SecurityAdvisory.class);

        final var task = new GitHubAdvisoryMirrorTask();
        final boolean createdOrUpdated = task.processAdvisory(advisory);
        assertThat(createdOrUpdated).isTrue();

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();
        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vuln);
        assertThat(aliases).isEmpty();
    }

    @Test
    public void testProcessAdvisoryVulnerableVersionRanges() throws Exception {
        var vs1 = new VulnerableSoftware();
        vs1.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind");
        vs1.setPurlType("maven");
        vs1.setPurlNamespace("com.fasterxml.jackson.core");
        vs1.setPurlName("jackson-databind");
        vs1.setVersionStartIncluding("2.13.0");
        vs1.setVersionEndIncluding("2.13.2.0");
        vs1.setVulnerable(true);
        vs1 = qm.persist(vs1);

        var vs2 = new VulnerableSoftware();
        vs2.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind");
        vs2.setPurlType("maven");
        vs2.setPurlNamespace("com.fasterxml.jackson.core");
        vs2.setPurlName("jackson-databind");
        vs2.setVersionEndExcluding("2.12.6.1");
        vs2.setVulnerable(true);
        vs2 = qm.persist(vs2);

        var vs3 = new VulnerableSoftware();
        vs3.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind");
        vs3.setPurlType("maven");
        vs3.setPurlNamespace("com.fasterxml.jackson.core");
        vs3.setPurlName("jackson-databind");
        vs3.setVersionStartIncluding("1");
        vs3.setVulnerable(true);
        vs3 = qm.persist(vs3);

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("GHSA-57j2-w4cx-62h2");
        existingVuln.setSource(Source.GITHUB);
        existingVuln.setVulnerableSoftware(List.of(vs1, vs2, vs3));
        existingVuln = qm.createVulnerability(existingVuln, false);
        qm.updateAffectedVersionAttribution(existingVuln, vs1, Source.OSV);
        qm.updateAffectedVersionAttribution(existingVuln, vs2, Source.OSV);
        qm.updateAffectedVersionAttribution(existingVuln, vs3, Source.GITHUB);

        // No vulnerable version range matching vs3 is created.
        // Because vs3 was attributed to GitHub, the association with the vulnerability
        // should be removed in the mirroring process.

        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "id": "GHSA-57j2-w4cx-62h2",
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "identifiers": [
                    {
                      "type": "CVE",
                      "value": "CVE-2020-36518"
                    }
                  ],
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:00Z",
                  "updatedAt": "2022-08-11T00:00:00Z",
                  "vulnerabilities": {
                    "edges": [
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": ">=2.13.0,<=2.13.2.0"
                        }
                      },
                      {
                        "node": {
                          "package": {
                            "ecosystem": "maven",
                            "name": "com.fasterxml.jackson.core:jackson-databind"
                          },
                          "vulnerableVersionRange": "<=2.12.6.0"
                        }
                      }
                    ]
                  }
                }
                """, SecurityAdvisory.class);

        // Run the mirror task
        final var task = new GitHubAdvisoryMirrorTask();
        final boolean createdOrUpdated = task.processAdvisory(advisory);
        assertThat(createdOrUpdated).isTrue();

        qm.getPersistenceManager().evictAll();
        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();

        final List<VulnerableSoftware> vsList = vuln.getVulnerableSoftware();
        assertThat(vsList).satisfiesExactlyInAnyOrder(
                // The version range reported by both GitHub and another source
                // must have attributions for both sources.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("2.13.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isEqualTo("2.13.2.0");
                    assertThat(vs.getVersionEndExcluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactlyInAnyOrder(
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.OSV),
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.GITHUB)
                    );
                },
                // The version range newly reported by GitHub must be attributed to only GitHub.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isEqualTo("2.12.6.0");
                    assertThat(vs.getVersionEndExcluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactlyInAnyOrder(
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.GITHUB)
                    );
                },
                // The version range that was reported by another source must be retained.
                // There must be no attribution to GitHub for this range.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("2.12.6.1");

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.OSV)
                    );
                }
        );
    }

    @Test
    public void shouldNotRetryOnResponseWithCode403() {
        final var httpResponse = new BasicHttpResponse(403);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    public void shouldRetryOnResponseWithCode429() {
        final var httpResponse = new BasicHttpResponse(429);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldRetryOnResponseWithCode503() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldRetryUpToSixAttempts() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();

        boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 6, httpContext);
        assertThat(shouldRetry).isTrue();

        shouldRetry = retryStrategy.retryRequest(httpResponse, 7, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    public void shouldRetryOnResponseWithCode403AndRetryAfterHeader() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("retry-after", /* 1min */ 60);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldRetryOnResponseWithCode429AndRetryAfterHeader() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("retry-after", /* 1min */ 60);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldNotRetryWhenRetryAfterExceedsMaxDelay() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("retry-after", /* 3min */ 180);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();

        httpResponse.setHeader("retry-after", /* 3min 1sec */ 181);
        shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    public void shouldRetryOnResponseWithCode403AndRateLimitHeaders() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("x-ratelimit-remaining", 6);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldRetryOnResponseWithCode429AndRateLimitHeaders() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 6);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldRetryWhenLimitResetIsShorterThanMaxDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().plusSeconds(/* 3min */ 180).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    public void shouldNotRetryWhenLimitResetExceedsMaxDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().plusSeconds(/* 3min 1sec */ 181).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    public void shouldUseRetryAfterHeaderForRetryDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("retry-after", /* 1min 6sec */ 66);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isEqualTo(66);
    }

    @Test
    public void shouldUseLimitResetHeaderForRetryDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.addHeader("x-ratelimit-reset", Instant.now().plusSeconds(66).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isCloseTo(66, Offset.offset(1L));
    }

    @Test
    public void shouldUseOneSecondAsDefaultRetryDelay() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubAdvisoryMirrorTask.HttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isEqualTo(1);
    }

}