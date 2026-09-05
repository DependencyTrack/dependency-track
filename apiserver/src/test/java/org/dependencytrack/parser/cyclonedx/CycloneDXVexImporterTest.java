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
import org.cyclonedx.Version;
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
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

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
            analysis.setJustification(
                    org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification
                            .PROTECTED_BY_MITIGATING_CONTROL);
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
        query.setParameters(project);
        final List<Analysis> analyses = query.executeList();

        // The VEX names sources three ways, and none of them matches how
        // Dependency-Track recorded the vulnerability:
        //
        // * "National Vulnerability Database" is not a name it uses.
        // * "OSSINDEX" is a name it uses but not for these vulnerabilities.
        // * The third entry has no source at all.
        //
        // All three resolve, because the vulnerability ID identifies them on its own.
        assertThat(analyses)
                .filteredOn(analysis -> analysis.getVulnerability().getVulnId().startsWith("CVE-"))
                .extracting(analysis -> analysis.getVulnerability().getVulnId())
                .containsExactlyInAnyOrder("CVE-2020-25649", "CVE-2020-25650", "CVE-2020-25651");

        final List<Analysis> sourceAudits = analyses.stream()
                .filter(analysis -> !analysis.getVulnerability().getVulnId().startsWith("CVE-"))
                .toList();
        assertThat(sources.size()).isEqualTo(sourceAudits.size());
        assertThat(sourceAudits).allSatisfy(analysis -> {
            assertThat(analysis.isSuppressed()).isTrue();
            assertThat(analysis.getAnalysisComments())
                    .satisfiesExactlyInAnyOrder(
                            comment -> {
                                assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                                assertThat(comment.getComment())
                                        .isEqualTo(String.format(
                                                "Analysis: %s → %s",
                                                AnalysisState.NOT_SET, AnalysisState.FALSE_POSITIVE));
                            },
                            comment -> {
                                assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                                assertThat(comment.getComment()).isEqualTo("Details: Unit test");
                            },
                            comment -> {
                                assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                                assertThat(comment.getComment())
                                        .isEqualTo(String.format(
                                                "Justification: %s → %s",
                                                AnalysisJustification.NOT_SET,
                                                AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL));
                            },
                            comment -> {
                                assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                                assertThat(comment.getComment()).isEqualTo("Suppressed");
                            });
            assertThat(analysis.getAnalysisDetails()).isEqualTo("Unit test");
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
        assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.UPDATE);
        assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .containsExactly("Vendor Response: NOT_SET → UPDATE");
    }

    @Test
    public void shouldApplyExportedVexAnalysisOnlyToAnalyzedComponent() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.0");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("1.0.0");
        qm.persist(componentB);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln.setComponents(List.of(componentA, componentB));
        qm.persist(vuln);
        qm.addVulnerability(vuln, componentA, "none");
        qm.addVulnerability(vuln, componentB, "none");

        qm.makeAnalysis(new MakeAnalysisCommand(componentA, vuln)
                .withState(AnalysisState.NOT_AFFECTED)
                .withJustification(AnalysisJustification.CODE_NOT_REACHABLE));

        final var exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VEX, qm);
        final byte[] vexBytes = exporter.export(
                        exporter.create(project, Version.VERSION_16), CycloneDXExporter.Format.JSON, Version.VERSION_16)
                .getBytes(StandardCharsets.UTF_8);

        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(componentA, vuln))
                .extracting(Analysis::getAnalysisState, Analysis::getAnalysisJustification)
                .containsExactly(AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE);
        assertThat(qm.getAnalysis(componentB, vuln)).isNull();
    }

    @Test
    public void shouldApplyAnalysisWhenSourceNameIsNotADependencyTrackSourceName() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": {
                        "name": "National Vulnerability Database"
                      },
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable"
                      },
                      "affects": [
                        { "ref": "project" }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(component, vuln))
                .extracting(Analysis::getAnalysisState)
                .isEqualTo(AnalysisState.NOT_AFFECTED);
    }

    @Test
    public void shouldApplyAnalysisWhenSourceIsAbsent() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable"
                      },
                      "affects": [
                        { "ref": "project" }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(component, vuln))
                .extracting(Analysis::getAnalysisState)
                .isEqualTo(AnalysisState.NOT_AFFECTED);
    }

    @Test
    public void shouldApplyAnalysisWhenSourceIsKnownButNotTheOneHoldingTheVulnerability() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": { "name": "OSSINDEX" },
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable"
                      },
                      "affects": [
                        { "ref": "project" }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(component, vuln))
                .extracting(Analysis::getAnalysisState)
                .isEqualTo(AnalysisState.NOT_AFFECTED);
    }

    @Test
    public void shouldUseSourceToDisambiguateVulnerabilityIdSharedByMultipleSources() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var nvdVuln = new Vulnerability();
        nvdVuln.setVulnId("CVE-2099-0001");
        nvdVuln.setSource(Vulnerability.Source.NVD);
        nvdVuln.setSeverity(Severity.HIGH);
        qm.persist(nvdVuln);
        qm.addVulnerability(nvdVuln, component, "none");

        final var osvVuln = new Vulnerability();
        osvVuln.setVulnId("CVE-2099-0001");
        osvVuln.setSource(Vulnerability.Source.OSV);
        osvVuln.setSeverity(Severity.HIGH);
        qm.persist(osvVuln);
        qm.addVulnerability(osvVuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": { "name": "NVD" },
                      "analysis": { "state": "not_affected", "justification": "code_not_reachable" },
                      "affects": [{ "ref": "project" }]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(component, nvdVuln))
                .extracting(Analysis::getAnalysisState)
                .isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(qm.getAnalysis(component, osvVuln)).isNull();
    }

    @Test
    public void shouldSkipWhenSourcelessVulnerabilityIdIsAmbiguous() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var nvdVuln = new Vulnerability();
        nvdVuln.setVulnId("CVE-2099-0001");
        nvdVuln.setSource(Vulnerability.Source.NVD);
        nvdVuln.setSeverity(Severity.HIGH);
        qm.persist(nvdVuln);
        qm.addVulnerability(nvdVuln, component, "none");

        final var osvVuln = new Vulnerability();
        osvVuln.setVulnId("CVE-2099-0001");
        osvVuln.setSource(Vulnerability.Source.OSV);
        osvVuln.setSeverity(Severity.HIGH);
        qm.persist(osvVuln);
        qm.addVulnerability(osvVuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "source": { "name": "Some Other Scanner" },
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable"
                      },
                      "affects": [
                        { "ref": "project" }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        // Guessing either one would be wrong, so neither is analyzed.
        assertThat(qm.getAnalysis(component, nvdVuln)).isNull();
        assertThat(qm.getAnalysis(component, osvVuln)).isNull();
    }

    @Test
    public void shouldSkipUnresolvableRefWhenSourceIsAbsent() throws ParseException {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2099-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "none");

        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "project",
                      "name": "acme-app",
                      "version": "1.0.0"
                    }
                  },
                  "vulnerabilities": [
                    {
                      "id": "CVE-2099-0001",
                      "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable"
                      },
                      "affects": [
                        { "ref": "no-such-ref" }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        vexImporter.applyVex(qm, BomParserFactory.createParser(vexBytes).parse(vexBytes), project);

        assertThat(qm.getAnalysis(component, vuln)).isNull();
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
        assertThat(analysis.getOwaspVector()).isEqualTo(OWASP_VECTOR);
        assertThat(analysis.getOwaspScore()).isEqualByComparingTo(new BigDecimal("7.5"));
        // An OWASP rating import must not override the finding severity; it falls back to the vulnerability.
        assertThat(analysis.getSeverity()).isNull();
        assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .contains("OWASP Vector: (None) → " + OWASP_VECTOR, "OWASP Score: (None) → 7.5");
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
        assertThat(analysis).isNotNull();
        assertThat(analysis.getOwaspVector()).isEqualTo(OWASP_VECTOR);
        assertThat(analysis.getOwaspScore()).isEqualByComparingTo(new BigDecimal("4.2"));
        assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(analysis.isSuppressed()).isFalse();
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
        assertThat(analysis.getOwaspVector()).isNull();
        assertThat(analysis.getOwaspScore()).isNull();
    }
}
