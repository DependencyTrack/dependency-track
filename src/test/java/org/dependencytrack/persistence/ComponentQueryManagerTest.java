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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.tasks.scanners.InternalAnalysisTask;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ComponentQueryManagerTest extends PersistenceCapableTest {

    private Project project;

    private Component createComponent(final String name, final String version, final String purl, final String cpe) {
        if (project == null) {
            project = qm.createProject("acme-app", null, "1.0.0", null, null, null, true, false);
        }
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setCpe(cpe);
        return qm.createComponent(component, false);
    }

    private VulnerableSoftware createPurlVulnerableSoftware(final String type, final String namespace, final String name) {
        final var vs = new VulnerableSoftware();
        vs.setPurlType(type);
        vs.setPurlNamespace(namespace);
        vs.setPurlName(name);
        vs.setVulnerable(true);
        return qm.persist(vs);
    }

    @Test
    void getCandidateComponentsReturnsEmptyListForNullOrEmptyInput() {
        assertThat(qm.getCandidateComponentsForVulnerableSoftware(null)).isEmpty();
        assertThat(qm.getCandidateComponentsForVulnerableSoftware(Collections.emptyList())).isEmpty();
    }

    @Test
    void getCandidateComponentsMatchesByPurlTypeNamespaceAndName() {
        final Component matching = createComponent("jackson-databind", "2.13.0",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", null);
        createComponent("other-lib", "1.0.0",
                "pkg:maven/com.acme/other-lib@1.0.0", null);

        final VulnerableSoftware vs = createPurlVulnerableSoftware("maven", "com.fasterxml.jackson.core", "jackson-databind");

        final List<Component> candidates = qm.getCandidateComponentsForVulnerableSoftware(List.of(vs));
        assertThat(candidates).hasSize(1);
        assertThat(candidates.get(0).getId()).isEqualTo(matching.getId());
    }

    @Test
    void getCandidateComponentsMatchesByPurlWithoutNamespace() {
        final Component matching = createComponent("lodash", "4.17.20",
                "pkg:npm/lodash@4.17.20", null);
        createComponent("express", "4.18.0",
                "pkg:npm/express@4.18.0", null);

        final VulnerableSoftware vs = createPurlVulnerableSoftware("npm", null, "lodash");

        final List<Component> candidates = qm.getCandidateComponentsForVulnerableSoftware(List.of(vs));
        assertThat(candidates).hasSize(1);
        assertThat(candidates.get(0).getId()).isEqualTo(matching.getId());
    }

    @Test
    void getCandidateComponentsMatchesByCpeVendorAndProduct() {
        final Component matching = createComponent("openssl", "1.1.1",
                null, "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*");
        createComponent("nginx", "1.20.0",
                null, "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*");

        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*");
        vs.setVendor("openssl");
        vs.setProduct("openssl");
        vs.setVulnerable(true);
        qm.persist(vs);

        final List<Component> candidates = qm.getCandidateComponentsForVulnerableSoftware(List.of(vs));
        assertThat(candidates).hasSize(1);
        assertThat(candidates.get(0).getId()).isEqualTo(matching.getId());
    }

    @Test
    void getCandidateComponentsDeduplicatesAcrossEntries() {
        final Component component = createComponent("jackson-databind", "2.13.0",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", null);

        final VulnerableSoftware vs1 = createPurlVulnerableSoftware("maven", "com.fasterxml.jackson.core", "jackson-databind");
        final VulnerableSoftware vs2 = createPurlVulnerableSoftware("maven", "com.fasterxml.jackson.core", "jackson-databind");

        final List<Component> candidates = qm.getCandidateComponentsForVulnerableSoftware(List.of(vs1, vs2));
        assertThat(candidates).hasSize(1);
        assertThat(candidates.get(0).getId()).isEqualTo(component.getId());
    }

    @Test
    void getCandidateComponentsSkipsEntriesWithoutIdentity() {
        createComponent("jackson-databind", "2.13.0",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", null);

        final var vs = new VulnerableSoftware();
        vs.setVulnerable(true);
        qm.persist(vs);

        assertThat(qm.getCandidateComponentsForVulnerableSoftware(List.of(vs))).isEmpty();
    }

    @Test
    void candidateComponentsAnalyzedByInternalAnalyzerProduceFindings() {
        // Documents the full flow triggered when an INTERNAL vulnerability is created or
        // updated via the REST API: candidate components are resolved and dispatched to
        // the internal analyzer, which performs the precise version-range matching.
        final Component component = createComponent("jackson-databind", "2.13.0",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", null);

        var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.fasterxml.jackson.core");
        vs.setPurlName("jackson-databind");
        vs.setVersionEndExcluding("2.13.1");
        vs.setVulnerable(true);
        vs = qm.persist(vs);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-2026-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability = qm.createVulnerability(vulnerability, false);
        vulnerability.setVulnerableSoftware(List.of(vs));

        final List<Component> candidates = qm.getCandidateComponentsForVulnerableSoftware(List.of(vs));
        assertThat(candidates).hasSize(1);

        new InternalAnalysisTask().analyze(candidates);

        assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
        assertThat(qm.getAllVulnerabilities(component).get(0).getVulnId()).isEqualTo("INT-2026-001");
    }
}
