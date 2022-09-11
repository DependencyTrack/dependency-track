package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class InternalAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testIssue1574() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);
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
    public void testVersionNA(){
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("Apache httpd");
        component.setVersion("2.4.53");
        component.setCpe("cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vs1 = new VulnerableSoftware();
        vs1.setCpe23("cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*");
        vs1.setPart("a");
        vs1.setVendor("apache");
        vs1.setProduct("http_server");
        vs1.setVersion("-");
        vs1.setVulnerable(true);
        var vs = qm.persist(vs1);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2007-6420");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vs));
        qm.createVulnerability(vulnerability, false);

        var vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
        vs2.setPart("a");
        vs2.setVendor("apache");
        vs2.setProduct("http_server");
        vs2.setVersion("*");
        vs2.setVulnerable(true);
        vs = qm.persist(vs2);

        var vulnerability202231813 = new Vulnerability();
        vulnerability202231813.setVulnId("CVE-2022-31813");
        vulnerability202231813.setSource(Vulnerability.Source.NVD);
        vulnerability202231813.setVulnerableSoftware(List.of(vs2));
        qm.createVulnerability(vulnerability202231813, false);

        var vs3 = new VulnerableSoftware();
        vs3.setCpe23("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
        vs3.setPart("a");
        vs3.setVendor("apache");
        vs3.setProduct("http_server");
        vs3.setVersionStartIncluding("2.4.0");
        vs3.setVersionEndIncluding("2.4.53");
        vs3.setVulnerable(true);
        vs = qm.persist(vs2);

        var vulnerability202226377 = new Vulnerability();
        vulnerability202226377.setVulnId("CVE-2022-266377");
        vulnerability202226377.setSource(Vulnerability.Source.NVD);
        vulnerability202226377.setVulnerableSoftware(List.of(vs3));
        qm.createVulnerability(vulnerability202226377, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(2);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2022-31813");
        assertThat(vulnerabilities.getList(Vulnerability.class).get(1).getVulnId()).isEqualTo("CVE-2022-266377");
    }

    @Test
    public void testVersionFirmwareNA(){
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("Intel 2000e firmware");
        component.setVersion("-");
        component.setCpe("cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vs1 = new VulnerableSoftware();
        vs1.setCpe23("cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*");
        vs1.setPart("o");
        vs1.setVendor("intel");
        vs1.setProduct("2000e_firmware");
        vs1.setVersion("-");
        vs1.setVulnerable(true);
        var vs = qm.persist(vs1);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2019-0174");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vs));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2019-0174");
    }

}