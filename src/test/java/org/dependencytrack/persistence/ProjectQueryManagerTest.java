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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ProjectQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testCloneProjectPreservesVulnerabilityAttributionDate() throws Exception {
        Project project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);
        Component comp = new Component();
        comp.setId(111L);
        comp.setName("name");
        comp.setProject(project);
        comp.setVersion("1.0");
        comp.setCopyright("Copyright Acme");
        qm.createComponent(comp, true);
        Vulnerability vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, comp, AnalyzerIdentity.INTERNAL_ANALYZER, "Vuln1", "http://vuln.com/vuln1", new Date(1708559165229L));
        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false, true, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);
        Assert.assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        Assert.assertNotNull(finding);
        Assert.assertFalse(finding.getAttribution().isEmpty());
        Assert.assertEquals(new Date(1708559165229L),finding.getAttribution().get("attributedOn"));
    }

}