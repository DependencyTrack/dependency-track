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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import net.javacrumbs.jsonunit.assertj.JsonAssert.ConfigurableJsonAssert;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.vulndatasource.osv.schema.Osv;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.vulndatasource.osv.ModelConverter.trimSummary;

class ModelConverterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .registerModule(new JavaTimeModule());
    private static final String DEFAULT_SOURCE_ECOSYSTEM = "maven";

    @Nested
    final class AliasHandlingTest {

        @Test
        void shouldIncludeAliasReferencesWhenEnabled() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-GHSA-77rv-6vfw-x4gc.json"), true, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "org.springframework.security.oauth:spring-security-oauth",
                                  "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "GHSA-77rv-6vfw-x4gc",
                                  "source": {
                                    "name": "GITHUB"
                                  },
                                  "references": [
                                    {
                                      "id": "CVE-2019-3778",
                                      "source": {
                                        "name": "NVD"
                                      }
                                    }
                                  ],
                                  "ratings": [
                                    {
                                      "score": 9.0,
                                      "severity": "SEVERITY_CRITICAL",
                                      "method": "SCORE_METHOD_CVSSV31",
                                      "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H"
                                    }
                                  ],
                                  "cwes": [601],
                                  "description": "Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be susceptible to an open redirector attack that can leak an authorization code.\\n\\nA malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the \\"redirect_uri\\" parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code.\\n\\nThis vulnerability exposes applications that meet all of the following requirements: Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses the DefaultRedirectResolver in the AuthorizationEndpoint. \\n\\nThis vulnerability does not expose applications that: Act in the role of an Authorization Server and uses a different RedirectResolver implementation other than DefaultRedirectResolver, act in the role of a Resource Server only (e.g. @EnableResourceServer), act in the role of a Client only (e.g. @EnableOAuthClient).",
                                  "published": "2019-03-14T15:39:30Z",
                                  "updated": "2022-06-09T07:01:32.587Z",
                                  "credits": {
                                    "individuals": [
                                      {
                                        "name": "Skywalker"
                                      },
                                      {
                                        "name": "Solo"
                                      }
                                    ]
                                  },
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/<2.0.17"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "dependency-track:vuln:title",
                                      "value": "Critical severity vulnerability that affects org.springframework.security.oauth:spring-security-oauth and org.springframework.security.oauth:spring-security-oauth2"
                                    },
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldOmitAliasReferencesWhenDisabled() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-GHSA-77rv-6vfw-x4gc.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThat(bov.getVulnerabilitiesList())
                    .singleElement()
                    .satisfies(v -> assertThat(v.getReferencesList()).isEmpty());
        }

    }

    @Nested
    final class RangeConversionTest {

        @Test
        void shouldConvertMultipleAffectedRanges() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-vulnerability-with-ranges.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "org.springframework.security.oauth:spring-security-oauth2",
                                  "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth2"
                                },
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "org.springframework.security.oauth:spring-security-oauth",
                                  "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "GSD-2022-1000008",
                                  "source": {
                                    "name": "OSV"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_UNKNOWN"
                                    }
                                  ],
                                  "description": "faker.js had it's version updated to 6.6.6 in NPM (which reports it as having 2,571 dependent packages that rely upon it) and the GitHub repo has been wiped of content. This appears to have been done intentionally as the repo only has a single commit (so it was likjely deleted, recreated and a single commit with \\"endgame\\" added). It appears that both GitHub and NPM have locked out the original developer accountbut that the faker.js package is still broken. Please note that this issue is directly related to GSD-2022-1000007 and appears to be part of the same incident. A fork of the repo with the original code appears to now be available at https://github.com/faker-js/faker",
                                  "published": "2022-01-09T02:46:05.199Z",
                                  "updated": "2022-01-09T11:37:01.199Z",
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "version": "1.0.0.RELEASE"
                                        },
                                        {
                                          "version": "1.0.1.RELEASE"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/<2.0.17"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/>=1|<2|>=3|<4"
                                        },
                                        {
                                          "range": "vers:maven/<1"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "version": "1.0.0.RELEASE"
                                        },
                                        {
                                          "version": "2.0.9.RELEASE"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/>=3.1.0|<3.3.0"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/>=10|<13"
                                        }
                                      ]
                                    },
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:maven/>=10|<=29.0"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "dependency-track:vuln:title",
                                      "value": "faker.js 6.6.6 is broken and the developer has wiped the original GitHub repo"
                                    },
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldConvertVulnerabilityWithoutRanges() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-vulnerability-no-range.json"), true, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "vulnerabilities": [
                                {
                                  "id": "GSD-2022-1000008",
                                  "source": {
                                    "name": "OSV"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_UNKNOWN"
                                    }
                                  ],
                                  "description": "faker.js had it's version updated to 6.6.6 in NPM (which reports it as having 2,571 dependent packages that rely upon it) and the GitHub repo has been wiped of content. This appears to have been done intentionally as the repo only has a single commit (so it was likjely deleted, recreated and a single commit with \\"endgame\\" added). It appears that both GitHub and NPM have locked out the original developer accountbut that the faker.js package is still broken. Please note that this issue is directly related to GSD-2022-1000007 and appears to be part of the same incident. A fork of the repo with the original code appears to now be available at https://github.com/faker-js/faker",
                                  "published": "2022-01-09T02:46:05.199Z",
                                  "updated": "2022-01-09T11:37:01.199Z",
                                  "properties": [
                                    {
                                      "name": "dependency-track:vuln:title",
                                      "value": "faker.js 6.6.6 is broken and the developer has wiped the original GitHub repo"
                                    },
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldConvertGitCommitHashRanges() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-git-commit-hash-ranges.json"), true, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "radare2",
                                  "purl": "pkg:generic/radare2"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "OSV-2021-1820",
                                  "source": {
                                    "name": "OSV"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_MEDIUM"
                                    }
                                  ],
                                  "description": "details",
                                  "published": "2022-06-19T00:00:52.240Z",
                                  "updated": "2022-06-19T00:00:52.240Z",
                                  "advisories": [
                                    {
                                      "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id\\u003d48098"
                                    }
                                  ],
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "version": "5.4.0-git"
                                        },
                                        {
                                          "version": "release-5.0.0"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "dependency-track:vuln:title",
                                      "value": "Heap-buffer-overflow in r_str_utf8_codepoint"
                                    },
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldUseLowestUpperBoundWhenMultiplePresent() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-git-upper-bound-range.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "k8s.io/kubernetes",
                                  "purl": "pkg:golang/k8s.io/kubernetes"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "GHSA-g42g-737j-qx6j",
                                  "source": {
                                    "name": "GITHUB"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_UNKNOWN"
                                    }
                                  ],
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:golang/<1.18.18"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldEmitWildcardRangeWhenNoUpperBound() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-git-no-upper-bound-range.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "github.com/blevesearch/bleve",
                                  "purl": "pkg:golang/github.com/blevesearch/bleve"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "GO-2022-0470",
                                  "source": {
                                    "name": "OSV"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_UNKNOWN"
                                    }
                                  ],
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:golang/*"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldEmitExactVersionWhenNoRange() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-vulnerability-exact-version.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "yandex-yt-yson-bindings",
                                  "purl": "pkg:npm/yandex-yt-yson-bindings"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "MAL-2023-995",
                                  "source": {
                                    "name": "OSV"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_CRITICAL"
                                    }
                                  ],
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "version": "103.99.99"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldDiscardEnumeratedVersionsWhenWildcardRangeIsAuthoritative() throws IOException {
            final var advisory = MAPPER.readValue(/* language=JSON */ """
                    {
                      "id": "UBUNTU-CVE-2024-99999",
                      "affected": [
                        {
                          "package": {
                            "name": "linux",
                            "ecosystem": "Ubuntu:24.04:LTS",
                            "purl": "pkg:deb/ubuntu/linux?arch=source&distro=noble"
                          },
                          "ranges": [
                            {
                              "type": "ECOSYSTEM",
                              "events": [
                                { "introduced": "0" }
                              ]
                            }
                          ],
                          "versions": [
                            "6.8.0-31.31",
                            "6.8.0-35.35",
                            "6.8.0-39.39"
                          ]
                        }
                      ]
                    }
                    """, Osv.class);

            final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "Ubuntu");

            assertThatBov(bov)
                    .inPath("$.vulnerabilities[0].affects[0].versions")
                    .isEqualTo(/* language=JSON */ """
                            [
                              { "range": "vers:deb/*" }
                            ]
                            """);
        }

        @Test
        void shouldResolveConflictingUpperBounds() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-git-conflict-upper-bound-range.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "components": [
                                {
                                  "type": "CLASSIFICATION_LIBRARY",
                                  "bomRef": "${json-unit.any-string}",
                                  "name": "github.com/argoproj/argo-cd",
                                  "purl": "pkg:golang/github.com/argoproj/argo-cd"
                                }
                              ],
                              "vulnerabilities": [
                                {
                                  "id": "GHSA-h4w9-6x78-8vrj",
                                  "source": {
                                    "name": "GITHUB"
                                  },
                                  "ratings": [
                                    {
                                      "severity": "SEVERITY_UNKNOWN"
                                    }
                                  ],
                                  "affects": [
                                    {
                                      "ref": "${json-unit.any-string}",
                                      "versions": [
                                        {
                                          "range": "vers:golang/>=1.0.0|<2.1.16"
                                        }
                                      ]
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

        @Test
        void shouldNotEmitGitRangesAsVers() throws IOException {
            final var advisory = MAPPER.readValue(/* language=JSON */ """
                    {
                      "id": "OSV-2026-0004",
                      "affected": [
                        {
                          "package": {
                            "name": "foo",
                            "ecosystem": "generic",
                            "purl": "pkg:generic/foo"
                          },
                          "ranges": [
                            {
                              "type": "GIT",
                              "events": [
                                {
                                  "introduced": "abc"
                                },
                                {
                                  "fixed": "def"
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                    """, Osv.class);

            final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "generic");

            assertThatBov(bov)
                    .inPath("$.vulnerabilities[0].affects[0]")
                    .isEqualTo(/* language=JSON */ """
                            {
                              "ref": "${json-unit.any-string}"
                            }
                            """);
        }

        @Test
        void shouldHandleAffectedWithoutDatabaseSpecific() throws IOException {
            final var advisory = MAPPER.readValue(/* language=JSON */ """
                    {
                      "id": "OSV-2026-0005",
                      "affected": [
                        {
                          "package": {
                            "name": "foo",
                            "ecosystem": "Go",
                            "purl": "pkg:golang/foo"
                          },
                          "ranges": [
                            {
                              "type": "SEMVER",
                              "events": [
                                {
                                  "introduced": "1.0.0"
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                    """, Osv.class);

            final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "Go");

            assertThatBov(bov)
                    .inPath("$.vulnerabilities[0].affects[0].versions[0].range")
                    .isEqualTo("\"vers:golang/>=1.0.0\"");
        }

    }

    @Nested
    final class SeverityDerivationTest {

        @Test
        void shouldFilterInvalidCvssVectors() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-vulnerability-invalid-cvss.json"), false, DEFAULT_SOURCE_ECOSYSTEM);

            assertThatBov(bov)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "vulnerabilities": [
                                {
                                  "id": "GHSA-77rv-6vfw-x4gc",
                                  "source": {
                                    "name": "GITHUB"
                                  },
                                  "ratings": [
                                    {
                                      "method": "SCORE_METHOD_CVSSV4",
                                      "score": 8.8,
                                      "severity": "SEVERITY_HIGH",
                                      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N"
                                    },
                                    {
                                      "score": 7.2,
                                      "severity": "SEVERITY_HIGH",
                                      "method": "SCORE_METHOD_CVSSV3",
                                      "vector": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                                    },
                                    {
                                      "score": 2.6,
                                      "severity": "SEVERITY_LOW",
                                      "method": "SCORE_METHOD_CVSSV2",
                                      "vector": "(AV:N/AC:H/Au:N/C:P/I:N/A:N)"
                                    }
                                  ],
                                  "properties": [
                                    {
                                      "name": "internal:osv:ecosystem",
                                      "value": "maven"
                                    }
                                  ]
                                }
                              ]
                            }
                            """);
        }

    }

    @Nested
    final class SummaryTrimmingTest {

        @Test
        void shouldTrimSummaryToMaxLength() {
            final String trimmed = trimSummary("In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.");

            assertThat(trimmed)
                    .hasSize(255)
                    .isEqualTo("In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not ne..");
        }

        @Test
        void shouldReturnShortSummaryUnchanged() {
            assertThat(trimSummary("I'm a short Summary")).isEqualTo("I'm a short Summary");
        }

        @Test
        void shouldReturnNullForNullSummary() {
            assertThat(trimSummary(null)).isNull();
        }

    }

    @Test
    void shouldIgnoreInvalidTimestamps() throws IOException {
        final var advisory = MAPPER.readValue(/* language=JSON */ """
                {
                  "id": "DEBIAN-CVE-2026-23040",
                  "modified": "0001-01-01T00:00:00Z",
                  "published": "0001-01-01T00:00:00Z"
                }
                """, Osv.class);

        final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "Debian");

        assertThatBov(bov).isEqualTo(/* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "DEBIAN-CVE-2026-23040",
                      "source": {
                        "name": "OSV"
                      },
                      "ratings": [
                        {
                          "severity": "SEVERITY_UNKNOWN"
                        }
                      ],
                      "properties": [
                        {
                          "name": "internal:osv:ecosystem",
                          "value": "Debian"
                        }
                      ]
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldExtractEmailsFromCreditContacts() throws IOException {
        final var advisory = MAPPER.readValue(/* language=JSON */ """
                {
                  "id": "OSV-2026-0002",
                  "credits": [
                    {
                      "name": "Alice",
                      "contact": [
                        "https://alice.example/",
                        "mailto:alice@example.com"
                      ]
                    },
                    {
                      "name": "Bob",
                      "contact": [
                        "https://bob.example/"
                      ]
                    },
                    {
                      "name": "Carol",
                      "contact": [
                        "carol@example.com"
                      ]
                    },
                    {
                      "name": "Dave",
                      "contact": [
                        "https://dave.example/",
                        "dave@example.com"
                      ]
                    }
                  ]
                }
                """, Osv.class);

        final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "Maven");

        assertThatBov(bov)
                .inPath("$.vulnerabilities[0].credits.individuals")
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "name": "Alice",
                            "email": "alice@example.com"
                          },
                          {
                            "name": "Bob"
                          },
                          {
                            "name": "Carol",
                            "email": "carol@example.com"
                          },
                          {
                            "name": "Dave",
                            "email": "dave@example.com"
                          }
                        ]
                        """);
    }

    @Nested
    final class DistroQualifierEnrichmentTest {

        @Test
        void shouldEnrichPurlsForRealDebianAdvisory() throws IOException {
            final Bom bov = new ModelConverter(MAPPER).convert(
                    loadOsvAdvisory("osv-DSA-5474-1.json"), false, "Debian");

            assertThatBov(bov)
                    .when(Option.IGNORING_ARRAY_ORDER)
                    .inPath("$.components")
                    .isEqualTo(/* language=JSON */ """
                            [
                              {
                                "type": "CLASSIFICATION_LIBRARY",
                                "bomRef": "${json-unit.any-string}",
                                "name": "intel-microcode",
                                "purl": "pkg:deb/debian/intel-microcode?arch=source&distro=debian-11"
                              },
                              {
                                "type": "CLASSIFICATION_LIBRARY",
                                "bomRef": "${json-unit.any-string}",
                                "name": "intel-microcode",
                                "purl": "pkg:deb/debian/intel-microcode?arch=source&distro=debian-12"
                              }
                            ]
                            """);
        }

        @Test
        void shouldPreserveExistingDistroQualifier() throws IOException {
            final var advisory = MAPPER.readValue(/* language=JSON */ """
                    {
                      "id": "DSA-TEST-1",
                      "affected": [
                        {
                          "package": {
                            "name": "intel-microcode",
                            "ecosystem": "Debian:13",
                            "purl": "pkg:deb/debian/intel-microcode?distro=bullseye"
                          },
                          "ranges": [
                            {
                              "type": "ECOSYSTEM",
                              "events": [
                                { "introduced": "0" },
                                { "fixed": "1.0" }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                    """, Osv.class);

            final Bom bov = new ModelConverter(MAPPER).convert(advisory, false, "Debian");

            assertThatBov(bov)
                    .inPath("$.components[0].purl")
                    .isEqualTo("pkg:deb/debian/intel-microcode?distro=bullseye");
        }

    }

    private static Osv loadOsvAdvisory(String resource) throws IOException {
        return MAPPER.readValue(ModelConverterTest.class.getResourceAsStream("/" + resource), Osv.class);
    }

    private static ConfigurableJsonAssert assertThatBov(Bom bov) throws InvalidProtocolBufferException {
        return assertThatJson(JsonFormat.printer().print(bov));
    }

}
