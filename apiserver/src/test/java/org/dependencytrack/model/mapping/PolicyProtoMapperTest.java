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
package org.dependencytrack.model.mapping;

import com.google.protobuf.util.JsonFormat;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class PolicyProtoMapperTest extends PersistenceCapableTest {

    @Test
    public void testMapVulnerabilityToProto() throws Exception {
        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-100");
        vulnAlias.setGhsaId("GHSA-100");
        vulnAlias.setSnykId("SNYK-100");

        final var epss = new Epss();
        epss.setCve("CVE-100");
        epss.setScore(BigDecimal.valueOf(0.6));
        epss.setPercentile(BigDecimal.valueOf(0.7));

        final var vuln = new Vulnerability();
        vuln.setUuid(UUID.fromString("4702f182-3b24-426a-a469-118dbe61bab7"));
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setAliases(List.of(vulnAlias));
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(Date.from(Instant.ofEpochSecond(666)));
        vuln.setPublished(Date.from(Instant.ofEpochSecond(777)));
        vuln.setUpdated(Date.from(Instant.ofEpochSecond(888)));
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV2Vector("cvssV2Vector");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(2.2));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(3.3));
        vuln.setCvssV3Vector("cvssV2Vector");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(4.4));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(5.5));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(6.6));
        vuln.setOwaspRRVector("owaspRrVector");
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(7.7));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(8.8));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(9.9));
        vuln.setEpss(epss);

        assertThatJson(JsonFormat.printer().print(PolicyProtoMapper.mapToProto(vuln)))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "uuid": "4702f182-3b24-426a-a469-118dbe61bab7",
                          "id": "CVE-100",
                          "source": "NVD",
                          "aliases": [
                            {
                              "id": "CVE-100",
                              "source": "NVD"
                            },
                            {
                              "id": "SNYK-100",
                              "source": "SNYK"
                            },
                            {
                              "id": "GHSA-100",
                              "source": "GITHUB"
                            }
                          ],
                          "cwes": [
                            666,
                            777
                          ],
                          "created": "1970-01-01T00:11:06Z",
                          "published": "1970-01-01T00:12:57Z",
                          "updated": "1970-01-01T00:14:48Z",
                          "severity": "MEDIUM",
                          "cvssv2BaseScore": 1.1,
                          "cvssv2ImpactSubscore": 3.3,
                          "cvssv2ExploitabilitySubscore": 2.2,
                          "cvssv2Vector": "cvssV2Vector",
                          "cvssv3BaseScore": 4.4,
                          "cvssv3ImpactSubscore": 6.6,
                          "cvssv3ExploitabilitySubscore": 5.5,
                          "cvssv3Vector": "cvssV2Vector",
                          "owaspRrLikelihoodScore": 8.8,
                          "owaspRrTechnicalImpactScore": 9.9,
                          "owaspRrBusinessImpactScore": 7.7,
                          "owaspRrVector": "owaspRrVector",
                          "epssScore": 0.6,
                          "epssPercentile": 0.7
                        }
                        """);
    }

    @Test
    public void testMapVulnerabilityWithNoFieldsSet() throws Exception {
        assertThatJson(JsonFormat.printer().print(PolicyProtoMapper.mapToProto(new Vulnerability()))).isEqualTo("{}");
    }

    @Test
    public void testMapVulnerabilityToProtoWhenNull() {
        assertThat(PolicyProtoMapper.mapToProto((Vulnerability) null))
                .isEqualTo(org.dependencytrack.proto.policy.v1.Vulnerability.getDefaultInstance());
    }

    @Test
    public void testMapVulnerabilityToProtoWhenPersistent() {
        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> PolicyProtoMapper.mapToProto(vuln))
                .withMessage("vuln must not be persistent");
    }

}