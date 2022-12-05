package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.Test;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class InternalAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testIssue1574() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("github.com/tidwall/gjson");
        component.setVersion("v1.6.0");
        component.setPurl("pkg:golang/github.com/tidwall/gjson@v1.6.0?type=module");
        component = qm.createComponent(component, false);

        var vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setPurlType("golang");
        vulnerableSoftware.setPurlNamespace("github.com/tidwall");
        vulnerableSoftware.setPurlName("gjson");
        vulnerableSoftware.setVersionEndExcluding("1.6.5");
        vulnerableSoftware.setVulnerable(true);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("GHSA-wjm3-fq3r-5x46");
        vulnerability.setSource(Vulnerability.Source.GITHUB);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("GHSA-wjm3-fq3r-5x46");
    }

    @Test
    public void testExactMatchWithNAUpdate() throws CpeParsingException, CpeEncodingException {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);
        var component = new Component();
        component.setProject(project);
        component.setGroup("xiph");
        component.setName("speex");
        component.setVersion("1.2");
        component.setCpe("cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vulnerableSoftware = ModelConverter.convertCpe23UriToVulnerableSoftware("cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*");
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2020-23904");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2020-23904");
    }

}