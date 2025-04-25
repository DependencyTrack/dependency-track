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
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindingTest extends PersistenceCapableTest {

    private final UUID projectUuid = UUID.randomUUID();
    private final Date attributedOn = new Date();
    private final Finding finding = new Finding(projectUuid, "component-uuid", "component-name", "component-group",
            "component-version", "component-purl", "component-cpe", "vuln-uuid", "vuln-source", "vuln-vulnId", "vuln-title",
            "vuln-subtitle", "vuln-description", "vuln-recommendation", Severity.HIGH, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4), BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
            "0.5", "0.9", null, AnalyzerIdentity.INTERNAL_ANALYZER, attributedOn, null, null, AnalysisState.NOT_AFFECTED, true);

    @Test
    void testComponent() {
        Map<String, Object> map = finding.getComponent();
        Assertions.assertEquals("component-uuid", map.get("uuid"));
        Assertions.assertEquals("component-name", map.get("name"));
        Assertions.assertEquals("component-group", map.get("group"));
        Assertions.assertEquals("component-version", map.get("version"));
        Assertions.assertEquals("component-purl", map.get("purl"));
    }

    @Test
    void testVulnerability() {
        Map<String, Object> map = finding.getVulnerability();
        Assertions.assertEquals("vuln-uuid", map.get("uuid"));
        Assertions.assertEquals("vuln-source", map.get("source"));
        Assertions.assertEquals("vuln-vulnId", map.get("vulnId"));
        Assertions.assertEquals("vuln-title", map.get("title"));
        Assertions.assertEquals("vuln-subtitle", map.get("subtitle"));
        //Assertions.assertEquals("vuln-description", map.get("description"));
        //Assertions.assertEquals("vuln-recommendation", map.get("recommendation"));
        Assertions.assertEquals(BigDecimal.valueOf(7.2), map.get("cvssV2BaseScore"));
        Assertions.assertEquals(BigDecimal.valueOf(8.4), map.get("cvssV3BaseScore"));
        Assertions.assertEquals(BigDecimal.valueOf(1.25), map.get("owaspLikelihoodScore"));
        Assertions.assertEquals(BigDecimal.valueOf(1.75), map.get("owaspTechnicalImpactScore"));
        Assertions.assertEquals(BigDecimal.valueOf(1.3), map.get("owaspBusinessImpactScore"));
        Assertions.assertEquals(Severity.HIGH.name(), map.get("severity"));
        Assertions.assertEquals(1, map.get("severityRank"));
    }

    @Test
    void testAnalysis() {
        Map<String, Object> map = finding.getAnalysis();
        Assertions.assertEquals(AnalysisState.NOT_AFFECTED, map.get("state"));
        Assertions.assertEquals(true, map.get("isSuppressed"));
    }

    @Test
    void testMatrix() {
        Assertions.assertEquals(projectUuid + ":component-uuid" + ":vuln-uuid", finding.getMatrix());
    }

    @Test
    void testGetCwes() {
        assertThat(Finding.getCwes("787,79,,89,"))
                .hasSize(3)
                .satisfiesExactly(
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(787),
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(79),
                        cwe -> assertThat(cwe.getCweId()).isEqualTo(89)
                );
    }

    @Test
    void testGetCwesWhenInputIsEmpty() {
        assertThat(Finding.getCwes("")).isNull();
        assertThat(Finding.getCwes(",")).isNull();
    }

    @Test
    void testGetCwesWhenInputIsNull() {
        assertThat(Finding.getCwes(null)).isNull();
    }

}
