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

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JvnDetailParserTest {

    @Test
    void parsesRealDetailWithMultipleVersionRanges() throws Exception {
        final List<JvnAdvisory> advisories;
        try (InputStream in = getClass().getResourceAsStream("/jvn-detail-with-range.xml")) {
            assertNotNull(in, "fixture jvn-detail-with-range.xml must be present");
            advisories = JvnDetailParser.parse(in);
        }

        assertEquals(1, advisories.size());
        final JvnAdvisory advisory = advisories.getFirst();
        assertEquals("JVNDB-2026-022538", advisory.jvnDbId());
        assertNotNull(advisory.title());

        // <Overview> is nested in <VulinfoDescription>; ensure it is extracted.
        assertNotNull(advisory.overview(), "expected the overview/description to be parsed");
        assertTrue(advisory.overview().contains("valuesFrom"));

        // <Impact><ImpactItem><Description> -> detail; <Solution><SolutionItem><Description> ->
        // recommendation. The unrelated <HistoryItem><Description> must not leak into either.
        assertNotNull(advisory.detail(), "expected the impact detail to be parsed");
        assertTrue(advisory.detail().contains("外部に漏れる"));
        assertFalse(advisory.detail().contains("掲載"), "history text must not leak into detail");
        assertNotNull(advisory.recommendation(), "expected the solution/recommendation to be parsed");
        assertTrue(advisory.recommendation().contains("ベンダ情報を参照"));

        assertFalse(advisory.cveIds().isEmpty(), "expected at least one CVE id");
        assertTrue(advisory.cveIds().stream().allMatch(id -> id.startsWith("CVE-")));

        // The fixture carries a <RelatedItem type="cwe"> of CWE-1287; its numeric id is collected,
        // and its glossary URL must NOT leak into the reference list.
        assertEquals(List.of(1287), advisory.cweIds());
        assertTrue(advisory.referenceUrls().stream().noneMatch(url -> url.contains("/cwe/")),
                "CWE glossary URLs must not be filed as references");

        assertEquals(1, advisory.affected().size());
        final JvnAdvisory.AffectedProduct product = advisory.affected().getFirst();
        assertEquals("cpe:/a:suse:rancher_fleet", product.cpe22());
        // The fixture lists four affected version ranges for this product.
        assertEquals(4, product.versionTexts().size());
        assertTrue(product.versionTexts().contains("0.15.0 以上 0.15.2 未満"));

        assertNotNull(advisory.datePublic());
    }
}
