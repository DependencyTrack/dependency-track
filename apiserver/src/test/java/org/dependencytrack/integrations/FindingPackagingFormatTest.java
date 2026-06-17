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
package org.dependencytrack.integrations;

import alpine.config.AlpineConfigKeys;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.hamcrest.CoreMatchers.equalTo;

public class FindingPackagingFormatTest extends PersistenceCapableTest {

    @Test
    @SuppressWarnings("unchecked")
    public void wrapperTest() {
        final Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, null, false);
        final var fpf = new FindingPackagingFormat(
                project.getUuid(),
                Collections.EMPTY_LIST
        );

        assertThatJson(fpf.getDocument())
                .withMatcher("appName", equalTo(ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_NAME, String.class)))
                .withMatcher("appVersion", equalTo(ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_VERSION, String.class)))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "version": "1.3",
                          "meta": {
                            "application": "${json-unit.matches:appName}",
                            "version": "${json-unit.matches:appVersion}",
                            "timestamp": "${json-unit.any-string}"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "Test",
                            "version": "1.0",
                            "description": "Sample project"
                          },
                          "findings": []
                        }
                        """);
    }

    @Test
    public void testFindingsVulnerabilityAndAliases() {
        final Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, null, false);

        final var findingRow1 = new FindingDao.FindingRow(project.getUuid(), UUID.randomUUID(), project.getName(), project.getVersion(),
                "component-name-1", null, "component-version", null, null, "Optional", true,
                UUID.randomUUID(), Vulnerability.Source.GITHUB, "vuln-vulnId-1", "vuln-title", "vuln-subtitle", "vuln-description",
                "vuln-recommendation", "vuln-references", Instant.now(), Severity.CRITICAL, null, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4), BigDecimal.valueOf(8.4),
                "cvssV2-vector", "cvssV3-vector", "cvssV4-vector", BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
                "owasp-vector", null, BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9),
                "oss-index", Instant.now(), null, null, AnalysisState.NOT_AFFECTED, true, 1);
        final Finding findingWithoutAlias = new Finding(findingRow1);

        var alias = new VulnerabilityAlias();
        alias.setCveId("someCveId");
        alias.setSonatypeId("someSonatypeId");
        alias.setGhsaId("someGhsaId");
        alias.setOsvId("someOsvId");
        alias.setSnykId("someSnykId");
        alias.setGsdId("someGsdId");
        alias.setVulnDbId("someVulnDbId");
        alias.setInternalId("someInternalId");

        var other = new VulnerabilityAlias();
        other.setCveId("anotherCveId");
        other.setSonatypeId("anotherSonatypeId");
        other.setGhsaId("anotherGhsaId");
        other.setOsvId("anotherOsvId");
        other.setSnykId("anotherSnykId");
        other.setGsdId("anotherGsdId");
        other.setInternalId("anotherInternalId");
        other.setVulnDbId(null);

        final var findingRow2 = new FindingDao.FindingRow(project.getUuid(), UUID.randomUUID(), project.getName(), project.getVersion(),
                "component-name-2", null, "component-version", null, null, "Required", true,
                UUID.randomUUID(), Vulnerability.Source.NVD, "vuln-vulnId-2", "vuln-title", "vuln-subtitle", "vuln-description",
                "vuln-recommendation", "vuln-references", Instant.now(), Severity.HIGH, null, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4), BigDecimal.valueOf(8.4),
                "cvssV2-vector", "cvssV3-vector", "cvssV4vector", BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
                "owasp-vector", List.of(alias, other), BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9),
                "internal", Instant.now(), null, null, AnalysisState.NOT_AFFECTED, true, 1);
        final Finding findingWithAlias = new Finding(findingRow2);

        final var fpf = new FindingPackagingFormat(
                project.getUuid(),
                List.of(findingWithoutAlias, findingWithAlias)
        );

        final String doc = fpf.getDocument();
        assertThatJson(doc)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "version": "1.3",
                          "meta": {
                            "application": "${json-unit.any-string}",
                            "version": "${json-unit.any-string}",
                            "timestamp": "${json-unit.any-string}"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "Test",
                            "version": "1.0",
                            "description": "Sample project"
                          },
                          "findings": [
                            {
                              "component": {
                                "uuid": "${json-unit.any-string}",
                                "name": "component-name-1",
                                "version": "component-version",
                                "project": "${json-unit.matches:projectUuid}",
                                "hasOccurrences": true,
                                "projectName": "Test",
                                "projectVersion": "1.0",
                                "scope": "Optional"
                              },
                              "vulnerability": {
                                "uuid": "${json-unit.any-string}",
                                "source": "GITHUB",
                                "vulnId": "vuln-vulnId-1",
                                "title": "vuln-title",
                                "subtitle": "vuln-subtitle",
                                "description": "vuln-description",
                                "recommendation": "vuln-recommendation",
                                "references": "vuln-references",
                                "severity": "CRITICAL",
                                "severityRank": 0,
                                "cvssV2BaseScore": 7.2,
                                "cvssV3BaseScore": 8.4,
                                "cvssV4Score": 8.4,
                                "cvssV2Vector": "cvssV2-vector",
                                "cvssV3Vector": "cvssV3-vector",
                                "cvssV4Vector": "cvssV4-vector",
                                "owaspLikelihoodScore": 1.25,
                                "owaspTechnicalImpactScore": 1.75,
                                "owaspBusinessImpactScore": 1.3,
                                "owaspRRVector": "owasp-vector",
                                "epssScore": 0.5,
                                "epssPercentile": 0.9,
                                "aliases": [],
                                "published": "${json-unit.any-string}"
                              },
                              "analysis": {
                                "state": "NOT_AFFECTED",
                                "isSuppressed": true
                              },
                              "attribution": {
                                "analyzerIdentity": "oss-index",
                                "attributedOn": "${json-unit.any-string}"
                              },
                              "matrix": "${json-unit.any-string}"
                            },
                            {
                              "component": {
                                "uuid": "${json-unit.any-string}",
                                "name": "component-name-2",
                                "version": "component-version",
                                "project": "${json-unit.matches:projectUuid}",
                                "hasOccurrences": true,
                                "projectName": "Test",
                                "projectVersion": "1.0",
                                "scope": "Required"
                              },
                              "vulnerability": {
                                "uuid": "${json-unit.any-string}",
                                "source": "NVD",
                                "vulnId": "vuln-vulnId-2",
                                "title": "vuln-title",
                                "subtitle": "vuln-subtitle",
                                "description": "vuln-description",
                                "recommendation": "vuln-recommendation",
                                "references": "vuln-references",
                                "severity": "HIGH",
                                "severityRank": 1,
                                "cvssV2BaseScore": 7.2,
                                "cvssV3BaseScore": 8.4,
                                "cvssV4Score": 8.4,
                                "cvssV2Vector": "cvssV2-vector",
                                "cvssV3Vector": "cvssV3-vector",
                                "cvssV4Vector": "cvssV4vector",
                                "owaspLikelihoodScore": 1.25,
                                "owaspTechnicalImpactScore": 1.75,
                                "owaspBusinessImpactScore": 1.3,
                                "owaspRRVector": "owasp-vector",
                                "epssScore": 0.5,
                                "epssPercentile": 0.9,
                                "aliases": [
                                  {
                                    "cveId": "someCveId",
                                    "ghsaId": "someGhsaId",
                                    "sonatypeId": "someSonatypeId",
                                    "osvId": "someOsvId",
                                    "snykId": "someSnykId",
                                    "vulnDbId": "someVulnDbId"
                                  },
                                  {
                                    "cveId": "anotherCveId",
                                    "ghsaId": "anotherGhsaId",
                                    "sonatypeId": "anotherSonatypeId",
                                    "osvId": "anotherOsvId",
                                    "snykId": "anotherSnykId"
                                  }
                                ],
                                "published": "${json-unit.any-string}"
                              },
                              "analysis": {
                                "state": "NOT_AFFECTED",
                                "isSuppressed": true
                              },
                              "attribution": {
                                "analyzerIdentity": "internal",
                                "attributedOn": "${json-unit.any-string}"
                              },
                              "matrix": "${json-unit.any-string}"
                            }
                          ]
                        }
                        """);
    }
}
