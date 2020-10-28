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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

public class FindingTest {

    private UUID projectUuid = UUID.randomUUID();
    private Date attributedOn = new Date();
    private Finding finding = new Finding(projectUuid, "component-uuid", "component-name", "component-group",
            "component-version", "component-purl", "vuln-uuid", "vuln-source", "vuln-vulnId", "vuln-title",
            "vuln-subtitle", "vuln-description", "vuln-recommendation", Severity.HIGH, "7.2", "8.4",
            AnalyzerIdentity.INTERNAL_ANALYZER, attributedOn, null, null, "79", "XSS", AnalysisState.NOT_AFFECTED, true);

    @Test
    public void testComponent() {
        Map map = finding.getComponent();
        Assert.assertEquals("component-uuid", map.get("uuid"));
        Assert.assertEquals("component-name", map.get("name"));
        Assert.assertEquals("component-group", map.get("group"));
        Assert.assertEquals("component-version", map.get("version"));
        Assert.assertEquals("component-purl", map.get("purl"));
    }

    @Test
    public void testVulnerability() {
        Map map = finding.getVulnerability();
        Assert.assertEquals("vuln-uuid", map.get("uuid"));
        Assert.assertEquals("vuln-source", map.get("source"));
        Assert.assertEquals("vuln-vulnId", map.get("vulnId"));
        Assert.assertEquals("vuln-title", map.get("title"));
        Assert.assertEquals("vuln-subtitle", map.get("subtitle"));
        //Assert.assertEquals("vuln-description", map.get("description"));
        //Assert.assertEquals("vuln-recommendation", map.get("recommendation"));
        Assert.assertEquals(Severity.HIGH.name(), map.get("severity"));
        Assert.assertEquals(1, map.get("severityRank"));
        Assert.assertEquals("79", map.get("cweId"));
        Assert.assertEquals("XSS", map.get("cweName"));
    }

    @Test
    public void testAnalysis() {
        Map map = finding.getAnalysis();
        Assert.assertEquals(AnalysisState.NOT_AFFECTED, map.get("state"));
        Assert.assertEquals(true, map.get("isSuppressed"));
    }

    @Test
    public void testMatrix() {
        Assert.assertEquals(projectUuid + ":component-uuid" + ":vuln-uuid", finding.getMatrix());
    }
}
