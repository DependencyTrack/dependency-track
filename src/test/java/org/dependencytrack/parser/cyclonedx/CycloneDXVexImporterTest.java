package org.dependencytrack.parser.cyclonedx;

import org.assertj.core.api.Assertions;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

import javax.jdo.Query;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

public class CycloneDXVexImporterTest extends PersistenceCapableTest {

    private CycloneDXVexImporter vexImporter = new CycloneDXVexImporter();

    @Test
    public void shouldAuditVulnerabilityFromAllSourcesUsingVex() throws URISyntaxException, IOException, ParseException {
        // Arrange
        var sources = Arrays.asList(Vulnerability.Source.values());
        var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final byte[] vexBytes = Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("vex-1.json").toURI()));
        var parser = BomParserFactory.createParser(vexBytes);
        var vex = parser.parse(vexBytes);

        List<org.cyclonedx.model.vulnerability.Vulnerability> audits = new LinkedList<>();

        var unknownVexSourceVulnerability = new Vulnerability();
        unknownVexSourceVulnerability.setVulnId("CVE-2020-25649");
        unknownVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        unknownVexSourceVulnerability.setSeverity(Severity.HIGH);
        unknownVexSourceVulnerability.setComponents(List.of(component));
        unknownVexSourceVulnerability = qm.createVulnerability(unknownVexSourceVulnerability, false);
        qm.addVulnerability(unknownVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        var mismatchVexSourceVulnerability = new Vulnerability();
        mismatchVexSourceVulnerability.setVulnId("CVE-2020-25650");
        mismatchVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        mismatchVexSourceVulnerability.setSeverity(Severity.HIGH);
        mismatchVexSourceVulnerability.setComponents(List.of(component));
        mismatchVexSourceVulnerability = qm.createVulnerability(mismatchVexSourceVulnerability, false);
        qm.addVulnerability(mismatchVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        var noVexSourceVulnerability = new Vulnerability();
        noVexSourceVulnerability.setVulnId("CVE-2020-25651");
        noVexSourceVulnerability.setSource(Vulnerability.Source.GITHUB);
        noVexSourceVulnerability.setSeverity(Severity.HIGH);
        noVexSourceVulnerability.setComponents(List.of(component));
        noVexSourceVulnerability = qm.createVulnerability(noVexSourceVulnerability, false);
        qm.addVulnerability(noVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        // Build vulnerabilities for each available and known vulnerability source
        for (var source : sources) {
            var vulnId = source.name().toUpperCase()+"-001";
            var vulnerability = new Vulnerability();
            vulnerability.setVulnId(vulnId);
            vulnerability.setSource(source);
            vulnerability.setSeverity(Severity.HIGH);
            vulnerability.setComponents(List.of(component));
            vulnerability = qm.createVulnerability(vulnerability, false);
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.NONE);

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
        qm.getPersistenceManager().refreshAll();

        // Act
        vexImporter.applyVex(qm, vex, project);

        // Assert
        final Query<Analysis> query = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        var analyses =  (List<Analysis>) query.execute(project);
        // CVE-2020-256[49|50|51] are not audited otherwise analyses.size would have been equal to sources.size()+3
        Assert.assertEquals(sources.size(), analyses.size());
        Assertions.assertThat(analyses).allSatisfy(analysis -> {
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25649");
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25650");
            Assertions.assertThat(analysis.isSuppressed()).isTrue();
            Assertions.assertThat(analysis.getAnalysisComments().size()).isEqualTo(3);
            Assertions.assertThat(analysis.getAnalysisComments()).satisfiesExactlyInAnyOrder(comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Analysis: %s → %s", AnalysisState.NOT_SET, AnalysisState.FALSE_POSITIVE));
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo("Details: Unit test");
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Justification: %s → %s", AnalysisJustification.NOT_SET, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL));
            });
            Assertions.assertThat(analysis.getAnalysisDetails()).isEqualTo("Unit test");
        });
    }

}
