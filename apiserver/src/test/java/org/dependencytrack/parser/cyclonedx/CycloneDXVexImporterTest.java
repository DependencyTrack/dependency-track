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

import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.BomParserFactory;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

public class CycloneDXVexImporterTest extends PersistenceCapableTest {

    private CycloneDXVexImporter vexImporter = new CycloneDXVexImporter();

    @Test
    public void shouldAuditVulnerabilityFromAllSourcesUsingVex() throws Exception {
        // Arrange
        var sources = Arrays.asList(Vulnerability.Source.values());
        var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final byte[] vexBytes = IOUtils.resourceToByteArray("/unit/vex-issue2549.json");
        var parser = BomParserFactory.createParser(vexBytes);
        var vex = parser.parse(vexBytes);

        List<org.cyclonedx.model.vulnerability.Vulnerability> audits = new LinkedList<>();

        var unknownVexSourceVulnerability = new Vulnerability();
        unknownVexSourceVulnerability.setVulnId("CVE-2020-25649");
        unknownVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        unknownVexSourceVulnerability.setSeverity(Severity.HIGH);
        unknownVexSourceVulnerability.setComponents(List.of(component));
        unknownVexSourceVulnerability = qm.createVulnerability(unknownVexSourceVulnerability);
        qm.addVulnerability(unknownVexSourceVulnerability, component, "none");

        var mismatchVexSourceVulnerability = new Vulnerability();
        mismatchVexSourceVulnerability.setVulnId("CVE-2020-25650");
        mismatchVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        mismatchVexSourceVulnerability.setSeverity(Severity.HIGH);
        mismatchVexSourceVulnerability.setComponents(List.of(component));
        mismatchVexSourceVulnerability = qm.createVulnerability(mismatchVexSourceVulnerability);
        qm.addVulnerability(mismatchVexSourceVulnerability, component, "none");

        var noVexSourceVulnerability = new Vulnerability();
        noVexSourceVulnerability.setVulnId("CVE-2020-25651");
        noVexSourceVulnerability.setSource(Vulnerability.Source.GITHUB);
        noVexSourceVulnerability.setSeverity(Severity.HIGH);
        noVexSourceVulnerability.setComponents(List.of(component));
        noVexSourceVulnerability = qm.createVulnerability(noVexSourceVulnerability);
        qm.addVulnerability(noVexSourceVulnerability, component, "none");

        // Build vulnerabilities for each available and known vulnerability source
        for (var source : sources) {
            var vulnId = source.name().toUpperCase() + "-001";
            var vulnerability = new Vulnerability();
            vulnerability.setVulnId(vulnId);
            vulnerability.setSource(source);
            vulnerability.setSeverity(Severity.HIGH);
            vulnerability.setComponents(List.of(component));
            vulnerability = qm.createVulnerability(vulnerability);
            qm.addVulnerability(vulnerability, component, "none");

            var audit = new org.cyclonedx.model.vulnerability.Vulnerability();
            audit.setBomRef(UUID.randomUUID().toString());
            audit.setId(vulnId);
            var auditSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
            auditSource.setName(source.name());
            audit.setSource(auditSource);
            var analysis = new org.cyclonedx.model.vulnerability.Vulnerability.Analysis();
            analysis.setState(org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.FALSE_POSITIVE);
            analysis.setDetail("Unit test");
            analysis.setJustification(org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_MITIGATING_CONTROL);
            audit.setAnalysis(analysis);
            var affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(vex.getMetadata().getComponent().getBomRef());
            audit.setAffects(List.of(affect));
            audits.add(audit);
        }
        audits.addAll(vex.getVulnerabilities());
        vex.setVulnerabilities(audits);

        // Act
        vexImporter.applyVex(qm, vex, project);

        // Assert
        final Query<Analysis> query = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        var analyses = (List<Analysis>) query.execute(project);
        // CVE-2020-256[49|50|51] are not audited otherwise analyses.size would have been equal to sources.size()+3
        org.junit.jupiter.api.Assertions.assertEquals(sources.size(), analyses.size());
        Assertions.assertThat(analyses).allSatisfy(analysis -> {
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25649");
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25650");
            Assertions.assertThat(analysis.isSuppressed()).isTrue();
            Assertions.assertThat(analysis.getAnalysisComments()).satisfiesExactlyInAnyOrder(comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Analysis: %s → %s", AnalysisState.NOT_SET, AnalysisState.FALSE_POSITIVE));
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo("Details: Unit test");
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Justification: %s → %s", AnalysisJustification.NOT_SET, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL));
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo("Suppressed");
            });
            Assertions.assertThat(analysis.getAnalysisDetails()).isEqualTo("Unit test");
        });
    }

    @Test
    public void shouldPersistLastResponseAndCommentEach() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        vuln.setComponents(List.of(component));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "Acme Example",
                      "version": "1.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": { "name": "NVD" },
                      "analysis": {
                        "response": ["will_not_fix", "update"]
                      },
                      "affects": [{ "ref": "project" }]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        final var vex = BomParserFactory.createParser(vexBytes).parse(vexBytes);

        vexImporter.applyVex(qm, vex, project);

        final Analysis analysis = qm.getAnalysis(component, vuln);
        Assertions.assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.UPDATE);
        Assertions.assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .containsExactly("Vendor Response: NOT_SET → UPDATE");
    }

    private static final String OWASP_VECTOR =
            "OWASP/SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3";

    @Test
    public void shouldApplyOwaspRatingFromVex() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        vuln.setComponents(List.of(component));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "version": 1,
                  "metadata": {
                    "component": { "type": "application", "bom-ref": "project", "name": "Acme Example", "version": "1.0" }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": { "name": "NVD" },
                      "analysis": { "state": "exploitable" },
                      "ratings": [
                        { "method": "OWASP", "vector": "%s", "score": 7.5 }
                      ],
                      "affects": [{ "ref": "project" }]
                    }
                  ]
                }
                """.formatted(OWASP_VECTOR).getBytes(StandardCharsets.UTF_8);
        final var vex = BomParserFactory.createParser(vexBytes).parse(vexBytes);

        vexImporter.applyVex(qm, vex, project);

        final Analysis analysis = qm.getAnalysis(component, vuln);
        Assertions.assertThat(analysis.getOwaspVector()).isEqualTo(OWASP_VECTOR);
        Assertions.assertThat(analysis.getOwaspScore()).isEqualByComparingTo(new BigDecimal("7.5"));
        // An OWASP rating import must not override the finding severity; it falls back to the vulnerability.
        Assertions.assertThat(analysis.getSeverity()).isNull();
        Assertions.assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .contains(
                        "OWASP Vector: (None) → " + OWASP_VECTOR,
                        "OWASP Score: (None) → 7.5");
    }

    @Test
    public void shouldApplyOwaspRatingWithoutAnalysisBlock() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0002");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        vuln.setComponents(List.of(component));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "version": 1,
                  "metadata": {
                    "component": { "type": "application", "bom-ref": "project", "name": "Acme Example", "version": "1.0" }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0002",
                      "source": { "name": "NVD" },
                      "ratings": [
                        { "method": "OWASP", "vector": "%s", "score": 4.2 }
                      ],
                      "affects": [{ "ref": "project" }]
                    }
                  ]
                }
                """.formatted(OWASP_VECTOR).getBytes(StandardCharsets.UTF_8);
        final var vex = BomParserFactory.createParser(vexBytes).parse(vexBytes);

        vexImporter.applyVex(qm, vex, project);

        final Analysis analysis = qm.getAnalysis(component, vuln);
        Assertions.assertThat(analysis).isNotNull();
        Assertions.assertThat(analysis.getOwaspVector()).isEqualTo(OWASP_VECTOR);
        Assertions.assertThat(analysis.getOwaspScore()).isEqualByComparingTo(new BigDecimal("4.2"));
        Assertions.assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
        Assertions.assertThat(analysis.isSuppressed()).isFalse();
    }

    @Test
    public void shouldIgnoreNonOwaspRatings() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0003");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        vuln.setComponents(List.of(component));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "version": 1,
                  "metadata": {
                    "component": { "type": "application", "bom-ref": "project", "name": "Acme Example", "version": "1.0" }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0003",
                      "source": { "name": "NVD" },
                      "analysis": { "state": "exploitable" },
                      "ratings": [
                        { "method": "CVSSv3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8 }
                      ],
                      "affects": [{ "ref": "project" }]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        final var vex = BomParserFactory.createParser(vexBytes).parse(vexBytes);

        vexImporter.applyVex(qm, vex, project);

        final Analysis analysis = qm.getAnalysis(component, vuln);
        Assertions.assertThat(analysis.getOwaspVector()).isNull();
        Assertions.assertThat(analysis.getOwaspScore()).isNull();
    }

}
