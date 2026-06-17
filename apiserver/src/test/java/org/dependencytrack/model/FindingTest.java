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
package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class FindingTest extends PersistenceCapableTest {

    private Finding finding;

    @BeforeEach
    public void setUp() {
        finding = createTestFinding();
    }

    @Test
    public void testComponent() {
        Map<String, Object> map = finding.getComponent();
        assertThat(map.get("uuid")).isNotNull();
        Assertions.assertEquals("component-name", map.get("name"));
        Assertions.assertEquals("component-group", map.get("group"));
        Assertions.assertEquals("component-version", map.get("version"));
        Assertions.assertEquals("pkg:maven/foo/bar@1.2.3", map.get("purl"));
        Assertions.assertEquals(Scope.REQUIRED.name(), map.get("scope"));
    }

    @Test
    public void testVulnerability() {
        Map<String, Object> map = finding.getVulnerability();
        assertThat(map.get("uuid")).isNotNull();
        Assertions.assertEquals(Vulnerability.Source.GITHUB, map.get("source"));
        Assertions.assertEquals("vuln-vulnId", map.get("vulnId"));
        Assertions.assertEquals("vuln-title", map.get("title"));
        Assertions.assertEquals("vuln-subtitle", map.get("subtitle"));
        Assertions.assertEquals("vuln-description", map.get("description"));
        Assertions.assertEquals("vuln-recommendation", map.get("recommendation"));
        Assertions.assertEquals(BigDecimal.valueOf(7.2), map.get("cvssV2BaseScore"));
        Assertions.assertEquals(BigDecimal.valueOf(8.4), map.get("cvssV3BaseScore"));
        Assertions.assertEquals("cvssV2-vector", map.get("cvssV2Vector"));
        Assertions.assertEquals("cvssV3-vector", map.get("cvssV3Vector"));
        Assertions.assertEquals(BigDecimal.valueOf(1.25), map.get("owaspLikelihoodScore"));
        Assertions.assertEquals(BigDecimal.valueOf(1.75), map.get("owaspTechnicalImpactScore"));
        Assertions.assertEquals(BigDecimal.valueOf(1.3), map.get("owaspBusinessImpactScore"));
        Assertions.assertEquals("owasp-vector", map.get("owaspRRVector"));
        Assertions.assertEquals(Severity.HIGH.name(), map.get("severity"));
        Assertions.assertEquals(1, map.get("severityRank"));
        Assertions.assertEquals(BigDecimal.valueOf(0.5), map.get("epssScore"));
        Assertions.assertEquals(BigDecimal.valueOf(0.9), map.get("epssPercentile"));
    }

    @Test
    public void testAnalysis() {
        Map<String, Object> map = finding.getAnalysis();
        Assertions.assertEquals(AnalysisState.NOT_AFFECTED, map.get("state"));
        Assertions.assertEquals(true, map.get("isSuppressed"));
    }

    @Test
    public void testMatrix() {
        assertThat(finding.getMatrix()).isNotNull();
    }

    @Test
    public void testGetCwes() {
        assertThat(Finding.getCwes(List.of(787,79,89)))
                .satisfiesExactly(
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(787),
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(79),
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(89)
                );
    }

    @Test
    public void testGetCwesWhenInputIsNullOrEmpty() {
        assertThat(Finding.getCwes(List.of())).isNull();
        assertThat(Finding.getCwes(null)).isNull();
    }

    @Test
    public void testGetCwesWhenInputIsNull() {
        assertThat(Finding.getCwes(null)).isNull();
    }

    private Finding createTestFinding() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);

        FindingDao.FindingRow findingRow = new FindingDao.FindingRow(project.getUuid(), UUID.randomUUID(), project.getName(), project.getVersion(),
                "component-name", "component-group", "component-version", "pkg:maven/foo/bar@1.2.3", "component-cpe", Scope.REQUIRED.name(),
                true, UUID.randomUUID(), Vulnerability.Source.GITHUB, "vuln-vulnId", "vuln-title", "vuln-subtitle", "vuln-description",
                "vuln-recommendation", "vuln-references", Instant.now(), Severity.HIGH, null, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4), BigDecimal.valueOf(8.4),
                "cvssV2-vector", "cvssV3-vector", "cvssV4-vector", BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
                "owasp-vector", null, BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9),
                "internal", Instant.now(), null, null, AnalysisState.NOT_AFFECTED, true, 1);

        return new Finding(findingRow);
    }
}
