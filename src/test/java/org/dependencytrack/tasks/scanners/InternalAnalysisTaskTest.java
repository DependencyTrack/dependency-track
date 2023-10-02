package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;

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

    @RunWith(JUnitParamsRunner.class)
    public static class CpeMatchingTest extends PersistenceCapableTest {

        private enum Expectation {
            MATCHES,
            DOES_NOT_MATCH
        }

        @Before
        public void setUp() {
            qm.createConfigProperty(
                    SCANNER_INTERNAL_ENABLED.getGroupName(),
                    SCANNER_INTERNAL_ENABLED.getPropertyName(),
                    "true",
                    SCANNER_INTERNAL_ENABLED.getPropertyType(),
                    SCANNER_INTERNAL_ENABLED.getDescription()
            );
        }

        private Object[] parameters() {
            return new Object[]{
                    // #2988: "other" attribute of source is NA, "other" attribute of target is ANY.
                    new Object[]{"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:NA", Expectation.MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                    // #2988: "target_hw" of source if x64, "target_hw" of target is ANY.
                    new Object[]{"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:x86:*", Expectation.MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                    // #2988: "vendor" of source contains wildcard, "vendor" of target is ANY.
                    new Object[]{"cpe:2.3:o:linu*:linux_kernel:5.15.37:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:o:*:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                    // #2580: Source vendor is , target vendor is wildcard.
                    new Object[]{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:o:*:linux_kernel:4.19.139:*:*:*:*:*:*:*"},
                    // #2994: "part" of source is "a", "part" of target is ANY.
                    new Object[]{"cpe:2.3:a:busybox:busybox:1.34.1:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:*:busybox:busybox:1.34.1:*:*:*:*:*:*:*"},
                    // #2894: "vendor" and "product" with different casing.
                    // Note: CPEs with uppercase "part" are considered invalid by the cpe-parser library.
                    new Object[]{"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:o:LiNuX:LiNuX_kErNeL:5.15.37:*:*:*:*:*:*:*"},
                    // #1832: "version" of source is NA, "version" of target is "2.4.54".
                    new Object[]{"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"},
                    // #1832: "version" of source is NA, "version" of target is ANY.
                    new Object[]{"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", Expectation.MATCHES, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
            };
        }

        @Test
        @Parameters(method = "parameters")
        public void test(final String source, final Expectation expectation, final String target) throws Exception {
            final VulnerableSoftware vs = ModelConverter.convertCpe23UriToVulnerableSoftware(source);
            vs.setVulnerable(true);
            qm.persist(vs);

            final var vuln = new Vulnerability();
            vuln.setVulnId("CVE-123");
            vuln.setSource(Vulnerability.Source.NVD);
            vuln.setVulnerableSoftware(List.of(vs));
            qm.persist(vuln);

            final var project = new Project();
            project.setName("acme-app");
            qm.persist(project);

            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            component.setCpe(target);
            qm.persist(component);

            new InternalAnalysisTask().inform(new InternalAnalysisEvent(qm.detach(Component.class, component.getId())));

            if (expectation == Expectation.MATCHES) {
                assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
            } else {
                assertThat(qm.getAllVulnerabilities(component)).isEmpty();
            }
        }

    }

}