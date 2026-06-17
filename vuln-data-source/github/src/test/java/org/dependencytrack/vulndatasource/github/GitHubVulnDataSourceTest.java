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
package org.dependencytrack.vulndatasource.github;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.util.JsonFormat;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_7.Bom;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GitHubVulnDataSourceTest {

    private GitHubSecurityAdvisoryClient advisoryClientMock;
    private WatermarkManager watermarkManagerMock;
    private GitHubVulnDataSource vulnDataSource;
    private ObjectMapper objectMapper;

    @BeforeEach
    void beforeEach() {
        advisoryClientMock = mock(GitHubSecurityAdvisoryClient.class);
        watermarkManagerMock = mock(WatermarkManager.class);
        vulnDataSource = new GitHubVulnDataSource(watermarkManagerMock, advisoryClientMock, true);
        objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Test
    void test() throws Exception {
        final var advisory = objectMapper.readValue(
                getClass().getResourceAsStream("/advisory.json"), SecurityAdvisory.class);

        when(advisoryClientMock.hasNext())
                .thenReturn(true)
                .thenReturn(false);
        when(advisoryClientMock.next())
                .thenReturn(List.of(advisory));

        assertThat(vulnDataSource).hasNext();
        final Bom bov = vulnDataSource.next();

        assertThatJson(JsonFormat.printer().print(bov))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vuln-description", Matchers.allOf(
                        Matchers.startsWith("In Bootstrap 4 before 4.3.1 and Bootstrap 3 before 3.4.1,"),
                        Matchers.hasLength(219)))
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "bomRef": "9407f313-a355-3a52-a697-ab76c6641d89",
                              "purl": "pkg:nuget/bootstrap"
                            },
                            {
                              "bomRef": "0e15be9a-cee8-3e0f-b101-6a7aa2d828ba",
                              "purl": "pkg:nuget/bootstrap.sass"
                            },
                            {
                              "bomRef": "ad335325-578a-334c-88a5-a64caa0c017e",
                              "purl": "pkg:nuget/Bootstrap.Less"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "GHSA-fxwm-579q-49qq",
                              "source": { "name": "GITHUB" },
                              "references": [
                                {
                                  "id": "CVE-2019-8331",
                                  "source": { "name":"NVD" }
                                }
                              ],
                              "description": "${json-unit.matches:vuln-description}",
                              "properties": [
                                  {
                                    "name": "dependency-track:vuln:title",
                                    "value": "Moderate severity vulnerability that affects Bootstrap.Less, bootstrap, and bootstrap.sass"
                                  }
                              ],
                              "published": "2019-02-22T20:54:40Z",
                              "updated": "2021-12-03T14:54:43Z",
                              "ratings": [
                                {
                                  "method": "SCORE_METHOD_OTHER",
                                  "severity": "SEVERITY_MEDIUM",
                                  "source": { "name": "GITHUB" }
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "9407f313-a355-3a52-a697-ab76c6641d89",
                                  "versions": [
                                    { "range": "vers:nuget/>=3.0.0|<3.4.1" },
                                    { "range": "vers:nuget/>=4.0.0|<4.3.1" }
                                  ]
                                },
                                {
                                  "ref": "0e15be9a-cee8-3e0f-b101-6a7aa2d828ba",
                                  "versions": [
                                    { "range": "vers:nuget/<4.3.1" }
                                  ]
                                },
                                {
                                  "ref": "ad335325-578a-334c-88a5-a64caa0c017e",
                                  "versions": [
                                    { "range": "vers:nuget/>=3.0.0|<3.4.1" }
                                  ]
                                }
                              ]
                            }
                          ],
                          "externalReferences": [
                            { "url": "https://github.com/advisories/GHSA-fxwm-579q-49qq" }
                          ]
                        }
                        """);

        vulnDataSource.markProcessed(bov);

        verify(watermarkManagerMock).maybeAdvance(eq(Instant.parse("2021-12-03T14:54:43Z")));
        verify(watermarkManagerMock).maybeCommit(eq(false));
    }

}