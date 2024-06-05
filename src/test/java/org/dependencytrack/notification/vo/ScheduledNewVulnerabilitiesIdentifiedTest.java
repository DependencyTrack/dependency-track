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
package org.dependencytrack.notification.vo;

import java.util.LinkedHashMap;
import java.util.List;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;

public class ScheduledNewVulnerabilitiesIdentifiedTest {
    @Test
    public void testVo() {
        Vulnerability critVuln = new Vulnerability();
        critVuln.setTitle("Critical Vulnerability");
        critVuln.setSeverity(Severity.CRITICAL);
        Vulnerability highVuln = new Vulnerability();
        highVuln.setTitle("High Vulnerability");
        highVuln.setSeverity(Severity.HIGH);
        Vulnerability mediumVuln = new Vulnerability();
        mediumVuln.setTitle("Medium Vulnerability");
        mediumVuln.setSeverity(Severity.MEDIUM);
        Vulnerability lowVuln = new Vulnerability();
        lowVuln.setTitle("Low Vulnerability");
        lowVuln.setSeverity(Severity.LOW);
        Vulnerability infoVuln = new Vulnerability();
        infoVuln.setTitle("Info Vulnerability");
        infoVuln.setSeverity(Severity.INFO);

        Project project1 = new Project();
        var project1Vulns = List.of(critVuln, highVuln, infoVuln);
        var projectVulnerabilitiesMap = new LinkedHashMap<Project, List<Vulnerability>>();
        projectVulnerabilitiesMap.put(project1, project1Vulns);
        Project project2 = new Project();
        var project2Vulns = List.of(mediumVuln, lowVuln);
        projectVulnerabilitiesMap.put(project2, project2Vulns);

        // ScheduledNewVulnerabilitiesIdentified vo = new ScheduledNewVulnerabilitiesIdentified(projectVulnerabilitiesMap);

        // Assert.assertEquals(2, vo.getNewProjectVulnerabilities().size());
        // Assert.assertEquals(project1Vulns, vo.getNewProjectVulnerabilities().get(project1));
        // Assert.assertEquals(project2Vulns, vo.getNewProjectVulnerabilities().get(project2));
        // Assert.assertEquals(2, vo.getNewProjectVulnerabilitiesBySeverity().size());
        // var projectVulnerabilitiesBySeverityMap = vo.getNewProjectVulnerabilitiesBySeverity();
        // Assert.assertEquals(3, projectVulnerabilitiesBySeverityMap.get(project1).size());
        // Assert.assertEquals(2, projectVulnerabilitiesBySeverityMap.get(project2).size());
        // Assert.assertEquals(1, projectVulnerabilitiesBySeverityMap.get(project1).get(Severity.CRITICAL).size());
        // Assert.assertEquals(1, projectVulnerabilitiesBySeverityMap.get(project1).get(Severity.HIGH).size());
        // Assert.assertEquals(1, projectVulnerabilitiesBySeverityMap.get(project1).get(Severity.INFO).size());
        // Assert.assertEquals(1, projectVulnerabilitiesBySeverityMap.get(project2).get(Severity.MEDIUM).size());
        // Assert.assertEquals(1, projectVulnerabilitiesBySeverityMap.get(project2).get(Severity.LOW).size());
        // Assert.assertEquals(5, vo.getNewVulnerabilitiesTotal().size());
        // Assert.assertEquals(List.of(critVuln, highVuln, infoVuln, mediumVuln, lowVuln), vo.getNewVulnerabilitiesTotal());
        // Assert.assertEquals(5, vo.getNewVulnerabilitiesTotalBySeverity().size());
        // var vulnerabilitiesBySeverity = vo.getNewVulnerabilitiesTotalBySeverity();
        // Assert.assertEquals(1, vulnerabilitiesBySeverity.get(Severity.CRITICAL).size());
        // Assert.assertEquals(1, vulnerabilitiesBySeverity.get(Severity.HIGH).size());
        // Assert.assertEquals(1, vulnerabilitiesBySeverity.get(Severity.MEDIUM).size());
        // Assert.assertEquals(1, vulnerabilitiesBySeverity.get(Severity.LOW).size());
        // Assert.assertEquals(1, vulnerabilitiesBySeverity.get(Severity.INFO).size());
    }
}
