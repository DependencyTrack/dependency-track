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
package org.dependencytrack.vulndatasource.jvn;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelConverterTest {

    @Test
    void convertsRealAdvisoryToBov() throws Exception {
        final List<JvnAdvisory> advisories;
        try (InputStream in = getClass().getResourceAsStream("/jvn-detail-with-range.xml")) {
            assertNotNull(in);
            advisories = JvnDetailParser.parse(in);
        }
        final Bom bom = ModelConverter.convert(advisories.getFirst());

        assertEquals(1, bom.getComponentsCount());
        final Component component = bom.getComponents(0);
        assertEquals("cpe:2.3:a:suse:rancher_fleet:*:*:*:*:*:*:*:*", component.getCpe());
        assertEquals("rancher_fleet", component.getName());

        assertEquals(1, bom.getVulnerabilitiesCount());
        final Vulnerability vuln = bom.getVulnerabilities(0);
        // Every advisory is stored as-is under the JVN source, keyed by its JVNDB id, even when
        // it carries a CVE (no CVE->NVD routing / dedup).
        assertEquals("JVNDB-2026-022538", vuln.getId());
        assertEquals("JVN", vuln.getSource().getName());

        assertEquals(1, vuln.getAffectsCount());
        final VulnerabilityAffects affects = vuln.getAffects(0);
        assertEquals(component.getBomRef(), affects.getRef());
        // Four affected version ranges in the fixture, all parseable to vers ranges.
        assertEquals(4, affects.getVersionsCount());
        assertTrue(affects.getVersionsList().stream()
                .anyMatch(v -> v.getRange().equals("vers:generic/>=0.15.0|<0.15.2")));
    }
}
