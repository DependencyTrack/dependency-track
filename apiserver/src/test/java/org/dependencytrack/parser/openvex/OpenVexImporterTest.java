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
import org.dependencytrack.parser.openvex.model.Openvex;
import org.dependencytrack.parser.openvex.model.Statement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OpenVexImporterTest extends PersistenceCapableTest {

    private final OpenVexImporter vexImporter = new OpenVexImporter();

    @ParameterizedTest
    @CsvSource({
            "NOT_AFFECTED,        NOT_AFFECTED, true",
            "AFFECTED,            EXPLOITABLE,  false",
            "FIXED,               RESOLVED,     true",
            "UNDER_INVESTIGATION, IN_TRIAGE,    false"})
    void testStatusMapping(Statement.Status status, AnalysisState expectedState, boolean expectedSuppression) {
        final var mappedState = OpenVexImporter.mapStatus(status);
        assertThat(mappedState).isEqualTo(expectedState);
        assertThat(OpenVexImporter.isSuppressed(mappedState)).isEqualTo(expectedSuppression);
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {
            "COMPONENT_NOT_PRESENT,                             CODE_NOT_PRESENT",
            "VULNERABLE_CODE_NOT_PRESENT,                       CODE_NOT_PRESENT",
            "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,               CODE_NOT_REACHABLE",
            "INLINE_MITIGATIONS_ALREADY_EXIST,                  PROTECTED_BY_MITIGATING_CONTROL",
            "VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY, null"})
    void testJustificationMapping(Statement.Justification justification,
            AnalysisJustification expectedJustification) {
        final var mappedJustification = OpenVexImporter.mapJustification(justification);
        assertThat(mappedJustification).isEqualTo(expectedJustification);
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
    void shouldSkipStatementWithoutProducts() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability)).isNull();
        assertThat(getAnalyses(project)).isEmpty();
    }

    @Test
    void shouldNotMatchComponentWhenQualifiersDiffer() {
        final Project project = createProject();
        final Component component =
                createComponent(project, "acme-lib", "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7" }],
                "status": "fixed"
                """)), project);

        // Same package coordinates, but different qualifiers: per the matching rules of the
        // go-vex reference implementation, this must NOT be treated as a match.
        assertThat(qm.getAnalysis(component, vulnerability)).isNull();
        assertThat(getAnalyses(project)).isEmpty();
    }

    @Test
    void shouldMatchComponentWithIdenticalQualifiers() {
        final Project project = createProject();
        final Component component =
                createComponent(project, "acme-lib", "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{ "@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(component, vulnerability))
                .extracting(Analysis::getAnalysisState, Analysis::isSuppressed)
                .containsExactly(AnalysisState.RESOLVED, true);
    }

    @Test
    void shouldApplyStatementToMatchingSubcomponent() {
        final Project project = createProject();
        final Component app = createComponent(project, "acme-app", "pkg:maven/com.acme/acme-app@1.0.0");
        final Component lib = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Component orphan = createComponent(project, "acme-orphan", "pkg:maven/com.acme/acme-orphan@1.0.0");
        createDependency(app, lib);

        final Vulnerability vulnApp = createFinding(project, app, "CVE-2099-0001");
        final Vulnerability vulnOrphan = createFinding(project, orphan, "CVE-2099-0002");

        // The vulnerability originates in acme-lib, which is included by acme-app, but not by
        // acme-orphan. Only the product including the subcomponent must remain a target.
        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [
                  {
                    "@id": "pkg:maven/com.acme/acme-app@1.0.0",
                    "subcomponents": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }]
                  },
                  {
                    "@id": "pkg:maven/com.acme/acme-orphan@1.0.0",
                    "subcomponents": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }]
                  }
                ],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(app, vulnApp))
                .extracting(Analysis::getAnalysisState, Analysis::isSuppressed)
                .containsExactly(AnalysisState.RESOLVED, true);
        assertThat(qm.getAnalysis(orphan, vulnOrphan)).isNull();
    }

    @Test
    void shouldApplyStatementWhenSubcomponentMatchesDirectly() {
        final Project project = createProject();
        final Component app = createComponent(project, "acme-app", "pkg:maven/com.acme/acme-app@1.0.0");
        final Vulnerability vulnerability = createFinding(project, app, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "@id": "pkg:maven/com.acme/acme-app@1.0.0",
                  "subcomponents": [{ "@id": "pkg:maven/com.acme/acme-app@1.0.0" }]
                }],
                "status": "fixed"
                """)), project);

        assertThat(qm.getAnalysis(app, vulnerability)).isNotNull();
    }

    @Test
    void shouldSkipStatementWhenSubcomponentNotFound() {
        final Project project = createProject();
        final Component app = createComponent(project, "acme-app", "pkg:maven/com.acme/acme-app@1.0.0");
        final Vulnerability vulnerability = createFinding(project, app, "CVE-2099-0001");

        vexImporter.applyVex(qm, parseDocument(documentWithStatement("""
                "vulnerability": { "name": "CVE-2099-0001" },
                "products": [{
                  "@id": "pkg:maven/com.acme/acme-app@1.0.0",
                  "subcomponents": [{ "@id": "pkg:maven/org.other/not-in-project@9.9.9" }]
                }],
                "status": "fixed"
                """)), project);

        // An unresolvable subcomponent must not cause analyses anywhere else.
        assertThat(qm.getAnalysis(app, vulnerability)).isNull();
        assertThat(getAnalyses(project)).isEmpty();
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
                "impact_statement": "The vulnerable code path is never executed",
                "status_notes": "Determined by static analysis"
                """)), project);

        final Analysis analysis = qm.getAnalysis(component, vulnerability);
        assertThat(analysis.getAnalysisDetails()).isEqualTo("""
                The vulnerable code path is never executed

                Determined by static analysis""");
        assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .anySatisfy(comment -> assertThat(comment).startsWith(
                        "Details: The vulnerable code path is never executed"));
    }

    @Test
    void shouldApplyLastStatementWhenMultipleTargetSamePair() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        // Statements are applied in chronological order of their timestamps. Later statements
        // override earlier ones, consistent with the specification's notion of documents being
        // sequences of statements.
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
                      "timestamp": "2023-01-08T19:02:03-06:00",
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
    void shouldApplyStatementsInTimestampOrderWhenPublishedOutOfOrder() {
        final Project project = createProject();
        final Component component = createComponent(project, "acme-lib", "pkg:maven/com.acme/acme-lib@1.0.0");
        final Vulnerability vulnerability = createFinding(project, component, "CVE-2099-0001");

        // The newer verdict ("fixed") appears first in the document, followed by the stale
        // verdict ("affected"). Applying in document order would let the stale verdict win;
        // chronological application must let the newer verdict override it.
        vexImporter.applyVex(qm, parseDocument(/* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2024-06-01T12:00:00Z",
                  "version": 1,
                  "statements": [
                    {
                      "timestamp": "2024-05-02T09:00:00Z",
                      "vulnerability": { "name": "CVE-2099-0001" },
                      "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                      "status": "fixed"
                    },
                    {
                      "timestamp": "2024-04-01T09:00:00Z",
                      "vulnerability": { "name": "CVE-2099-0001" },
                      "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                      "status": "affected",
                      "action_statement": "No fix available yet"
                    }
                  ]
                }
                """), project);

        assertThat(qm.getAnalysis(component, vulnerability))
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

    private void createDependency(final Component parent, final Component child) {
        parent.setDirectDependencies("[{\"uuid\": \"%s\"}]".formatted(child.getUuid()));
        qm.persist(parent);
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

    private static Openvex parseDocument(final String json) {
        return OpenVexParser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

}
