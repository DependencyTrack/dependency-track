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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class GroupedFindingTest extends PersistenceCapableTest {
    private GroupedFinding groupedFinding;

    @BeforeEach
    public void setUp() {
        groupedFinding = createTestFinding();
    }

    @Test
    public void testVulnerability() {
        Map map = groupedFinding.getVulnerability();
        assertEquals(Vulnerability.Source.GITHUB, map.get("source"));
        assertEquals("vuln-vulnId", map.get("vulnId"));
        assertEquals("vuln-title", map.get("title"));
        assertEquals(Severity.HIGH, map.get("severity"));
        assertNotNull(map.get("published"));
        assertEquals(BigDecimal.valueOf(8.5), map.get("cvssV2BaseScore"));
        assertEquals(BigDecimal.valueOf(8.4), map.get("cvssV3BaseScore"));
        assertEquals(3, map.get("affectedProjectCount"));
    }

    @Test
    public void testAttribution() {
        Map map = groupedFinding.getAttribution();
        assertEquals("internal", map.get("analyzerIdentity"));
    }

    private GroupedFinding createTestFinding() {
        FindingDao.GroupedFindingRow findingRow = new FindingDao.GroupedFindingRow(
                Vulnerability.Source.GITHUB,
                "vuln-vulnId",
                "vuln-title",
                Severity.HIGH,
                BigDecimal.valueOf(8.5),
                BigDecimal.valueOf(8.4),
                BigDecimal.valueOf(8.4),
                BigDecimal.valueOf(0.4),
                BigDecimal.valueOf(0.5),
                Instant.now(),
                null,
                "internal",
                3,
                1);
        return new GroupedFinding(findingRow);
    }
}