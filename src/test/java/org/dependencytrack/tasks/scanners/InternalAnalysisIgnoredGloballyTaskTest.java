package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class InternalAnalysisIgnoredGloballyTaskTest extends PersistenceCapableTest {

    @Test
    public void testIssueIgnoredGlobally1574() throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException {
        final Map<String, String> env = System.getenv();
        final Field envField = env.getClass().getDeclaredField("m");
        try {
            envField.setAccessible(true);
            ((Map<String, String>) envField.get(env)).put("IGNORED_ADVISORIES", "GHSA-wjm3-fq3r-5x46");

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
            assertThat(vulnerabilities.getTotal()).isEqualTo(0);
        } finally {
            ((Map<String, String>) envField.get(env)).remove("IGNORED_ADVISORIES");  // this doesn't work!
            envField.setAccessible(false);
        }
    }
}
