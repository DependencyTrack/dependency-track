package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.jupiter.api.Test;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InternalAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    void testIssue1574() {
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
        vulnerability = qm.createVulnerability(vulnerability, false);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("GHSA-wjm3-fq3r-5x46");
    }

    @Test
    void testPurlAnalysisNotSkippedWhenCpeIsInvalid() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("jackson-databind");
        component.setVersion("2.13.0");
        component.setCpe("cpe:invalid");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0");
        component = qm.createComponent(component, false);

        var purlVs = new VulnerableSoftware();
        purlVs.setPurlType("maven");
        purlVs.setPurlNamespace("com.fasterxml.jackson.core");
        purlVs.setPurlName("jackson-databind");
        purlVs.setVersionEndExcluding("2.13.1");
        purlVs.setVulnerable(true);
        purlVs = qm.persist(purlVs);

        var ghsaVuln = new Vulnerability();
        ghsaVuln.setVulnId("GHSA-0000-0000-0001");
        ghsaVuln.setSource(Vulnerability.Source.GITHUB);
        ghsaVuln = qm.createVulnerability(ghsaVuln, false);
        ghsaVuln.setVulnerableSoftware(List.of(purlVs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).getFirst().getVulnId()).isEqualTo("GHSA-0000-0000-0001");
    }

    @Test
    void testComponentWithBothValidCpeAndPurl() throws CpeParsingException, CpeEncodingException {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("jackson-databind");
        component.setVersion("2.13.0");
        component.setCpe("cpe:2.3:a:fasterxml:jackson-databind:2.13.0:*:*:*:*:*:*:*");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0");
        component = qm.createComponent(component, false);

        var cpeVs = ModelConverter.convertCpe23UriToVulnerableSoftware(
                "cpe:2.3:a:fasterxml:jackson-databind:2.13.0:*:*:*:*:*:*:*");
        cpeVs = qm.persist(cpeVs);

        var cveVuln = new Vulnerability();
        cveVuln.setVulnId("CVE-2022-00001");
        cveVuln.setSource(Vulnerability.Source.NVD);
        cveVuln = qm.createVulnerability(cveVuln, false);
        cveVuln.setVulnerableSoftware(List.of(cpeVs));

        var purlVs = new VulnerableSoftware();
        purlVs.setPurlType("maven");
        purlVs.setPurlNamespace("com.fasterxml.jackson.core");
        purlVs.setPurlName("jackson-databind");
        purlVs.setVersionEndExcluding("2.13.1");
        purlVs.setVulnerable(true);
        purlVs = qm.persist(purlVs);

        var ghsaVuln = new Vulnerability();
        ghsaVuln.setVulnId("GHSA-0000-0000-0001");
        ghsaVuln.setSource(Vulnerability.Source.GITHUB);
        ghsaVuln = qm.createVulnerability(ghsaVuln, false);
        ghsaVuln.setVulnerableSoftware(List.of(purlVs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(2);
        assertThat(vulnerabilities.getList(Vulnerability.class))
                .extracting(Vulnerability::getVulnId)
                .containsExactlyInAnyOrder("CVE-2022-00001", "GHSA-0000-0000-0001");
    }

    @Test
    void testCpeVersionDiffersFromComponentVersion() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("stm32l4_firmware");
        component.setVersion("1.2.3");
        component.setCpe("cpe:2.3:o:st:stm32l4_firmware:-:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vs = ModelConverter.convertCpe23UriToVulnerableSoftware(
                "cpe:2.3:o:st:stm32l4_firmware:-:*:*:*:*:*:*:*");
        vs = qm.persist(vs);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2023-00001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln = qm.createVulnerability(vuln, false);
        vuln.setVulnerableSoftware(List.of(vs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulns = qm.getVulnerabilities(component);
        assertThat(vulns.getTotal()).isEqualTo(1);
        assertThat(vulns.getList(Vulnerability.class).getFirst().getVulnId()).isEqualTo("CVE-2023-00001");
    }

    @Test
    void testCpeVersionUsedInsteadOfComponentVersion() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("product");
        component.setVersion("1.5.0");
        component.setCpe("cpe:2.3:a:vendor:product:5.0:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vs = ModelConverter.convertCpe23UriToVulnerableSoftware(
                "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs = qm.persist(vs);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2023-00002");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln = qm.createVulnerability(vuln, false);
        vuln.setVulnerableSoftware(List.of(vs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulns = qm.getVulnerabilities(component);
        assertThat(vulns.getTotal()).isEqualTo(0);
    }

    @Test
    void testPurlVersionDiffersFromComponentVersion() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("lib");
        component.setVersion("1.0-SNAPSHOT");
        component.setPurl("pkg:maven/com.example/lib@1.0.0");
        component = qm.createComponent(component, false);

        var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("lib");
        vs.setVersionEndExcluding("1.0.1");
        vs.setVulnerable(true);
        vs = qm.persist(vs);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2023-00003");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln = qm.createVulnerability(vuln, false);
        vuln.setVulnerableSoftware(List.of(vs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulns = qm.getVulnerabilities(component);
        assertThat(vulns.getTotal()).isEqualTo(1);
        assertThat(vulns.getList(Vulnerability.class).getFirst().getVulnId()).isEqualTo("CVE-2023-00003");
    }

    @Test
    void testCpeWithAnyVersionMatchesEverything() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("product");
        component.setVersion("2.5.0");
        component.setCpe("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vs = ModelConverter.convertCpe23UriToVulnerableSoftware(
                "cpe:2.3:a:vendor:product:2.5.0:*:*:*:*:*:*:*");
        vs = qm.persist(vs);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2023-00004");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln = qm.createVulnerability(vuln, false);
        vuln.setVulnerableSoftware(List.of(vs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulns = qm.getVulnerabilities(component);
        assertThat(vulns.getTotal()).isEqualTo(1);
        assertThat(vulns.getList(Vulnerability.class).getFirst().getVulnId()).isEqualTo("CVE-2023-00004");
    }

    @Test
    void testPurlWithNullVersionNoMatch() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/lib");
        component = qm.createComponent(component, false);

        var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("lib");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs = qm.persist(vs);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2023-00005");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln = qm.createVulnerability(vuln, false);
        vuln.setVulnerableSoftware(List.of(vs));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulns = qm.getVulnerabilities(component);
        assertThat(vulns.getTotal()).isEqualTo(0);
    }

    @Test
    void testExactMatchWithNAUpdate() throws CpeParsingException, CpeEncodingException {
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
        vulnerability = qm.createVulnerability(vulnerability, false);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2020-23904");
    }

}