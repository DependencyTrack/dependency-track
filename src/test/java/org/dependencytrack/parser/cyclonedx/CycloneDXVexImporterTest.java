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

        // Vulnerabilities for the VEX are dynamically built for each available vulnerability source
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
        vex.setVulnerabilities(audits);
        qm.getPersistenceManager().refreshAll();

        // Act
        vexImporter.applyVex(qm, vex, project);

        // Assert
        final Query<Analysis> query = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        var analyses =  (List<Analysis>) query.execute(project);
        Assert.assertEquals(sources.size(), analyses.size());
        Assertions.assertThat(analyses).allSatisfy(analysis -> {
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
