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

class GroupedFindingTest extends PersistenceCapableTest {

    private final Date published = new Date();
    private final GroupedFinding groupedFinding = new GroupedFinding("vuln-source", "vuln-vulnId", "vuln-title",
            Severity.HIGH, BigDecimal.valueOf(8.5), BigDecimal.valueOf(8.4), null, null, null, AnalyzerIdentity.INTERNAL_ANALYZER, published, null, 3);


    @Test
    void testVulnerability() {
        Map<String, Object> map = groupedFinding.getVulnerability();
        Assertions.assertEquals("vuln-source", map.get("source"));
        Assertions.assertEquals("vuln-vulnId", map.get("vulnId"));
        Assertions.assertEquals("vuln-title", map.get("title"));
        Assertions.assertEquals(Severity.HIGH, map.get("severity"));
        Assertions.assertEquals(published, map.get("published"));
        Assertions.assertEquals(BigDecimal.valueOf(8.5), map.get("cvssV2BaseScore"));
        Assertions.assertEquals(BigDecimal.valueOf(8.4), map.get("cvssV3BaseScore"));
        Assertions.assertEquals(3, map.get("affectedProjectCount"));
    }

    @Test
    void testAttribution() {
        Map<String, Object> map = groupedFinding.getAttribution();
        Assertions.assertEquals(AnalyzerIdentity.INTERNAL_ANALYZER, map.get("analyzerIdentity"));
    }
}
