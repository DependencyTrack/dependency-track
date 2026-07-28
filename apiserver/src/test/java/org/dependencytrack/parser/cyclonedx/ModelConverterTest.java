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
package org.dependencytrack.parser.cyclonedx;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ModelConverterTest extends PersistenceCapableTest {

    @Test
    void shouldSkipFindingWhoseComponentWasDeleted() {
        final Project project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component = qm.createComponent(component, false);
        qm.addVulnerability(vulnerability, component, "internal");

        // Resolve the findings up front, mirroring what the exporter does before conversion.
        final List<Finding> findings = withJdbiHandle(handle ->
                handle.attach(FindingDao.class).getFindings(project.getId(), true));
        assertThat(findings).hasSize(1);

        // Simulate the component being deleted in the window between the findings query
        // and the export (e.g. a concurrent re-analysis or manual deletion).
        final Component deletedComponent = component;
        withJdbiHandle(handle -> handle.attach(ComponentDao.class).deleteComponent(deletedComponent.getUuid()));

        // Before the fix this threw a NullPointerException and aborted the whole export.
        assertThatNoException().isThrownBy(() ->
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings));

        final List<org.cyclonedx.model.vulnerability.Vulnerability> result =
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings);
        assertThat(result).isEmpty();
    }

    @Test
    void shouldConvertFindingWithResolvableComponent() {
        final Project project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component = qm.createComponent(component, false);
        qm.addVulnerability(vulnerability, component, "internal");

        final List<Finding> findings = withJdbiHandle(handle ->
                handle.attach(FindingDao.class).getFindings(project.getId(), true));

        final List<org.cyclonedx.model.vulnerability.Vulnerability> result =
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings);
        assertThat(result).hasSize(1);
        assertThat(result.getFirst().getId()).isEqualTo("INT-001");
    }
}
