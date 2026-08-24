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
package org.dependencytrack.parser.openvex;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OpenVexImporterTest extends PersistenceCapableTest {

    private final OpenVexImporter vexImporter = new OpenVexImporter();

    @Test
    void shouldMapEverySupportedStatusToAnalysisState() {
        record StatusMappingCase(
                String statusLabel,
                AnalysisState expectedState,
                boolean expectedSuppression) {
        }

        // Suppression follows the same policy as CycloneDX VEX imports:
        // FALSE_POSITIVE, NOT_AFFECTED, and RESOLVED states are considered suppressed.
        final var cases = List.of(
                new StatusMappingCase("not_affected", AnalysisState.NOT_AFFECTED, true),
                new StatusMappingCase("affected", AnalysisState.EXPLOITABLE, false),
                new StatusMappingCase("fixed", AnalysisState.RESOLVED, true),
                new StatusMappingCase("under_investigation", AnalysisState.IN_TRIAGE, false));

        int vulnCounter = 0;
        for (final var caseDefinition : cases) {
            final Project project = qm.createProject("acme-app-" + vulnCounter, null, "1.0", null, null, null, null, false);
            final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
            final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-%04d".formatted(vulnCounter++));

            vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                    "vulnerability": { "name": "%s" },
                    "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0", "identifiers": { "purl": "pkg:maven/com.acme/acme-lib@1.0.0" } }],
                    "status": "%s",
                    %s"""
                    .formatted(vulnerability.getVulnId(), caseDefinition.statusLabel(),
                            switch (caseDefinition.expectedState()) {
                                // Both statuses require additional fields per specification.
                                case NOT_AFFECTED -> "\"justification\": \"component_not_present\"";
                                case EXPLOITABLE -> "\"action_statement\": \"Upgrade immediately\"";
                                default -> "\"irrelevant\": true";
                            }))), project);

            assertThat(qm.getAnalysis(component, vulnerability))
                    .as("Status %s must map to %s", caseDefinition.statusLabel(), caseDefinition.expectedState())
                    .extracting(Analysis::getAnalysisState, Analysis::isSuppressed)
                    .containsExactly(caseDefinition.expectedState(), caseDefinition.expectedSuppression());
        }
    }

    @Test
    void shouldMapJustificationsWithDependencyTrackEquivalent() {
        record JustificationMappingCase(String justificationLabel, AnalysisJustification expectedJustification) {
        }

        final var cases = List.of(
                new JustificationMappingCase("component_not_present", AnalysisJustification.CODE_NOT_PRESENT),
                new JustificationMappingCase("vulnerable_code_not_present", AnalysisJustification.CODE_NOT_PRESENT),
                new JustificationMappingCase("vulnerable_code_not_in_execute_path", AnalysisJustification.CODE_NOT_REACHABLE),
                new JustificationMappingCase("inline_mitigations_already_exist", AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL),
                new JustificationMappingCase("vulnerable_code_cannot_be_controlled_by_adversary", null));

        int vulnCounter = 100;
        for (final var caseDefinition : cases) {
            final Project project = qm.createProject("acme-app-" + vulnCounter, null, "1.0", null, null, null, null, false);
            final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
            final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-%04d".formatted(vulnCounter++));

            vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                    "vulnerability": { "name": "%s" },
                    "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0", "identifiers": { "purl": "pkg:maven/com.acme/acme-lib@1.0.0" } }],
                    "status": "not_affected",
                    "justification": "%s\"""".formatted(vulnerability.getVulnId(), caseDefinition.justificationLabel()))), project);

            final Analysis analysis = qm.getAnalysis(component, vulnerability);
            assertThat(analysis).isNotNull();
            assertThat(analysis.getAnalysisJustification())
                    .as("Justification %s must map to %s",
                            caseDefinition.justificationLabel(), caseDefinition.expectedJustification())
                    .isEqualTo(caseDefinition.expectedJustification() != null
                            ? caseDefinition.expectedJustification()
                            // Dependency-Track records NOT_SET where no justification applies.
                            : AnalysisJustification.NOT_SET);
            if (caseDefinition.expectedJustification() != null) {
                assertThat(analysis.getAnalysisComments())
                        .extracting(AnalysisComment::getComment)
                        .contains("Justification: %s → %s".formatted(
                                AnalysisJustification.NOT_SET, caseDefinition.expectedJustification()));
            }
        }
    }

    @Test
    void shouldNotApplyJustificationWhenStatusIsNotNotAffected() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed",
                "justification": "component_not_present"
                """ /* Redundant per spec, and contradicting the status; must be ignored. */)), project);

        assertThat(qm.getAnalysis(component, vulnerability))
                .extracting(Analysis::getAnalysisState, Analysis::getAnalysisJustification)
                .containsExactly(AnalysisState.RESOLVED, AnalysisJustification.NOT_SET);
    }

    @Test
    void shouldResolveVulnerabilityByName() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, qm.getVulnerabilityByVulnId("NVD", "CVE-2099-0001"))).isNotNull();
    }

    @Test
    void shouldResolveVulnerabilityByAlias() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");

        // Documents published by GitHub-based tooling often name GHSA IDs,
        // while Dependency-Track knows the vulnerability by its CVE ID.
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2099-0001");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, component, "none");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": {
                  "name": "GHSA-jfh8-c2jp-5v3q",
                  "aliases": ["CVE-2099-0001"]
                },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNotNull();
    }

    @Test
    void shouldSkipStatementWhenVulnerabilityIsUnknown() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-404" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNull();
    }

    @Test
    void shouldSkipStatementWhenVulnerabilityIdIsAmbiguousAcrossSources() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");

        var nvdVuln = new Vulnerability();
        nvdVuln.setVulnId("CVE-2099-0001");
        nvdVuln.setSource(Vulnerability.Source.NVD);
        nvdVuln.setSeverity(Severity.HIGH);
        nvdVuln = qm.createVulnerability(nvdVuln);
        qm.addVulnerability(nvdVuln, component, "none");

        var osvVuln = new Vulnerability();
        osvVuln.setVulnId("CVE-2099-0001");
        osvVuln.setSource(Vulnerability.Source.OSV);
        osvVuln.setSeverity(Severity.HIGH);
        osvVuln = qm.createVulnerability(osvVuln);
        qm.addVulnerability(osvVuln, component, "none");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        // Guessing either one would be wrong, so neither is analyzed.
        assertThat(qm.getAnalysis(component, nvdVuln)).isNull();
        assertThat(qm.getAnalysis(component, osvVuln)).isNull();
    }

    @Test
    void shouldSkipStatementWhenNameAndAliasIdentifyDifferentVulnerabilities() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");

        var ghsaVuln = new Vulnerability();
        ghsaVuln.setVulnId("GHSA-jfh8-c2jp-5v3q");
        ghsaVuln.setSource(Vulnerability.Source.GITHUB);
        ghsaVuln.setSeverity(Severity.HIGH);
        ghsaVuln = qm.createVulnerability(ghsaVuln);
        qm.addVulnerability(ghsaVuln, component, "none");

        var nvdVuln = new Vulnerability();
        nvdVuln.setVulnId("CVE-2099-0001");
        nvdVuln.setSource(Vulnerability.Source.NVD);
        nvdVuln.setSeverity(Severity.HIGH);
        nvdVuln = qm.createVulnerability(nvdVuln);
        qm.addVulnerability(nvdVuln, component, "none");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": {
                  "name": "GHSA-jfh8-c2jp-5v3q",
                  "aliases": ["CVE-2099-0001"]
                },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        // Name and alias identify two distinct vulnerabilities known to Dependency-Track.
        // Guessing either one would potentially suppress the wrong finding.
        assertThat(qm.getAnalysis(component, ghsaVuln)).isNull();
        assertThat(qm.getAnalysis(component, nvdVuln)).isNull();
    }

    @Test
    void shouldResolveProductByIdentifiersPurl() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "@id": "https://example.com/some-iri",
                  "identifiers": { "purl": "pkg:maven/com.acme/acme-lib@1.0.0" }
                }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNotNull();
    }

    @Test
    void shouldResolveProductByPurlShapedId() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNotNull();
    }

    @Test
    void shouldResolveProductByCpe23Identifier() {
        final Project project = createProject();

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Application");
        component.setVersion("1.0.0");
        component.setCpe("cpe:2.3:a:acme:acme_application:1.0.0:*:*:*:*:*:*:*");
        qm.createComponent(component, false);

        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "identifiers": { "cpe23": "cpe:2.3:a:acme:acme_application:1.0.0:*:*:*:*:*:*:*" }
                }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNotNull();
    }

    @Test
    void shouldFallBackToCpeWhenPurlDoesNotMatch() {
        final Project project = createProject();

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Application");
        component.setCpe("cpe:2.3:a:acme:acme_application:1.0.0:*:*:*:*:*:*:*");
        qm.createComponent(component, false);

        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "identifiers": {
                    "purl": "pkg:maven/com.acme/not-in-this-project@1.0.0",
                    "cpe23": "cpe:2.3:a:acme:acme_application:1.0.0:*:*:*:*:*:*:*"
                  }
                }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNotNull();
    }

    @Test
    void shouldSkipProductThatCannotBeResolved() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "identifiers": { "purl": "pkg:maven/org.other/not-present@9.9.9" }
                }],
                "status": "fixed"
                """)), project);

        // The unresolved product must not cause analyses anywhere else.
        assertThat(qm.getAnalysis(component, vulnerability)).isNull();
        assertThat(getAnalyses(project)).isEmpty();
    }

    @Test
    void shouldSkipProductIdentifiedByHashOnly() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "@id": "https://registry.example.com/git@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNull();
    }

    @Test
    void shouldApplyStatementToAllComponentsOfEquivalentIdentity() {
        final Project project = createProject();

        // Two components with equivalent identity, e.g. installed in different environments.
        final var componentA = createComponent(project, "acme-lib-env-a", "pkg:maven/com.acme/acme-lib@1.0.0");
        final var componentB = createComponent(project, "acme-lib-env-b", "pkg:maven/com.acme/acme-lib@1.0.0");

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2099-0001");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, componentA, "none");
        qm.addVulnerability(vulnerability, componentB, "none");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(componentA, vulnerability)).isNotNull();
        assertThat(qm.getAnalysis(componentB, vulnerability)).isNotNull();
    }

    @Test
    void shouldApplyMultiProductStatementOnlyToIntendedComponents() {
        final Project project = createProject();
        final Component componentA = createComponent(project, "acme-lib-a", "pkg:maven/com.acme/acme-lib-a@1.0.0");
        final Component componentB = createComponent(project, "acme-lib-b", "pkg:maven/com.acme/acme-lib-b@1.0.0");
        final Component componentWithoutVuln = createComponent(project, "acme-lib-c", "pkg:maven/com.acme/acme-lib-c@1.0.0");
        createComponent(project, "unrelated", "pkg:maven/org.unrelated/unrelated@1.0.0");

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2099-0001");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, componentA, "none");
        qm.addVulnerability(vulnerability, componentB, "none");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [
                  { "@id": "pkg:maven/com.acme/acme-lib-a@1.0.0" },
                  { "@id": "pkg:maven/org.does/not-exist@1.0.0" },
                  { "@id": "pkg:maven/com.acme/acme-lib-b@1.0.0" }
                ],
                "status": "not_affected",
                "justification": "component_not_present"
                """)), project);

        assertThat(qm.getAnalysis(componentA, vulnerability)).isNotNull();
        assertThat(qm.getAnalysis(componentB, vulnerability)).isNotNull();
        // The unresolvable product must not affect unrelated components.
        assertThat(qm.getAnalysis(componentWithoutVuln, vulnerability)).isNull();
    }

    @Test
    void shouldPreserveImpactAndActionStatementsInDetails() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": "The vulnerable code path is never executed"
                """)), project);

        final Analysis analysis = qm.getAnalysis(component, vulnerability);
        assertThat(analysis.getAnalysisDetails()).isEqualTo("The vulnerable code path is never executed");
        assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .contains("Details: The vulnerable code path is never executed");
    }

    @Test
    void shouldApplyLastStatementWhenMultipleTargetSamePair() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        // Statements are applied in document order. Later statements override earlier ones,
        // consistent with the specification's notion of documents being sequences of statements.
        vexImporter.applyVex(qm, parseDocument(/* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-09T09:08:42-06:00",
                  "version": 2,
                  "statements": [
                    {
                      "timestamp": "2023-01-08T18:02:03-06:00",
                      "vulnerability": { "name": "CVE-2099-0001" },
                      "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                      "status": "affected",
                      "action_statement": "No fix available yet"
                    },
                    {
                      "vulnerability": { "name": "CVE-2099-0001" },
                      "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                      "status": "fixed"
                    }
                  ]
                }
                """), project);

        final Analysis analysis = qm.getAnalysis(component, vulnerability);
        assertThat(analysis)
                .extracting(Analysis::getAnalysisState, Analysis::isSuppressed)
                .containsExactly(AnalysisState.RESOLVED, true);
    }

    @Test
    void shouldSkipImportForProjectWithoutFindings() {
        final Project project = createProject();
        createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                "status": "fixed"
                """)), project);

        assertThat(getAnalyses(project)).isEmpty();
    }

    private List<Analysis> getAnalyses(final Project project) {
        final javax.jdo.Query<Analysis> query = qm.getPersistenceManager().newQuery(Analysis.class,
                "project == :project");
        query.setParameters(project);
        return List.copyOf(query.executeList());
    }

    private Project createProject() {
        return qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
    }

    private Component createComponent(final Project project, final String name, final String purl) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion("1.0.0");
        component.setPurl(purl);
        return qm.createComponent(component, false);
    }

    private Vulnerability createFinding(final Project project, final Component component, final String vulnId) {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, component, "none");
        return vulnerability;
    }

    /**
     * Wraps the given statement fields (as raw JSON) into a valid OpenVEX document.
     */
    private static String documentWithStatement(final String statementFields) {
        return /* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03-06:00",
                  "version": 1,
                  "statements": [
                    {
                      %s
                    }
                  ]
                }
                """.formatted(statementFields);
    }

    private static OpenVexDocument parseDocument(final String json) {
        return OpenVexParser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

}
