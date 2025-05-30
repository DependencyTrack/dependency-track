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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import alpine.event.framework.Event;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.times;

class ProjectQueryManagerTest extends PersistenceCapableTest {

    @Test
    void testCloneProjectPreservesVulnerabilityAttributionDate() throws Exception {
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
        Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false,
                true, false, false, false, false, false);
        List<Finding> findings = qm.getFindings(clonedProject);
        Assertions.assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        Assertions.assertNotNull(finding);
        Assertions.assertFalse(finding.getAttribution().isEmpty());
        Assertions.assertEquals(new Date(1708559165229L), finding.getAttribution().get("attributedOn"));
    }

    @Test
    void testUpdateProjectPreventCollectionProjectWithExistingComponentsTest() {
        Project project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);
        Component comp = new Component();
        comp.setId(111L);
        comp.setName("name");
        comp.setProject(project);
        comp.setVersion("1.0");
        comp.setCopyright("Copyright Acme");
        qm.createComponent(comp, true);

        // avoid direct persistent update in next step
        final Project detached = qm.detach(Project.class, project.getId());
        detached.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> qm.updateProject(detached, false))
                .withMessage("Project cannot be made a collection project while it has components or services!");
    }

    @Test
    void testUpdateProjectPreventCollectionProjectWithExistingServiceTest() {
        Project project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, true, false);
        ServiceComponent service = new ServiceComponent();
        service.setName("name");
        service.setProject(project);
        service.setVersion("1.0");
        qm.createServiceComponent(service, false);

        // avoid direct persistent update in next step
        final Project detached = qm.detach(Project.class, project.getId());
        detached.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> qm.updateProject(detached, false))
                .withMessage("Project cannot be made a collection project while it has components or services!");
    }
    @Test
    public void testCloneProjectMetricUpdate() throws Exception {
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

        try (MockedStatic<Event> mockedEvent = Mockito.mockStatic(Event.class)) {
            Project clonedProject = qm.clone(project.getUuid(), "1.1.0", false, false,
                    true, false, false, false, false, false);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            mockedEvent.verify(() -> Event.dispatch(eventCaptor.capture()), times(4));

            Event updateCloneMetricsEvent = eventCaptor.getAllValues().get(3);
            Assertions.assertTrue(updateCloneMetricsEvent instanceof ProjectMetricsUpdateEvent);
            ProjectMetricsUpdateEvent projectMetricsEvent = (ProjectMetricsUpdateEvent) updateCloneMetricsEvent;
            Assertions.assertEquals(clonedProject.getUuid(), projectMetricsEvent.getUuid());
        }
    }

}