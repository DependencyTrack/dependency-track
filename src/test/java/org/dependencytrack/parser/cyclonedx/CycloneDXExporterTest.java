package org.dependencytrack.parser.cyclonedx;

import org.cyclonedx.exception.GeneratorException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatNoException;

public class CycloneDXExporterTest extends PersistenceCapableTest {

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3834
    public void testSchemaValidityOfExportedVexWithMultipleComponentsWithSameVulnerability() throws GeneratorException {

        var exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VEX, qm);

        var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var componentAWithTheVulnerability = new Component();
        componentAWithTheVulnerability.setProject(project);
        componentAWithTheVulnerability.setName("Acme Component");
        componentAWithTheVulnerability.setVersion("1.0");
        componentAWithTheVulnerability = qm.createComponent(componentAWithTheVulnerability, false);

        var componentBWithTheVulnerability = new Component();
        componentBWithTheVulnerability.setProject(project);
        componentBWithTheVulnerability.setName("Acme Component");
        componentBWithTheVulnerability.setVersion("1.1");
        componentBWithTheVulnerability = qm.createComponent(componentBWithTheVulnerability, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-29041");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);
        qm.addVulnerability(vulnerability, componentAWithTheVulnerability, AnalyzerIdentity.NONE);
        qm.addVulnerability(vulnerability, componentBWithTheVulnerability, AnalyzerIdentity.NONE);

        var vexBytes = exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON).getBytes();

        var validator = new CycloneDxValidator();

        assertThatNoException()
                .isThrownBy(() -> validator.validate(vexBytes));
    }
}