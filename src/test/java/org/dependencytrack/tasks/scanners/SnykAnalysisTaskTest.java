package org.dependencytrack.tasks.scanners;

import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.CweImporter;
import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class SnykAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testHandleSuccessfulResponse() throws Exception {
        new CweImporter().processCweDefinitions(); // Necessary for resolving CWEs

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/snyk-vuln.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        Component component = new Component();
        component.setPurl("pkg:npm/moment@2.24.0");
        component.setUuid(UUID.randomUUID());
        component.setName("test-snyk");

        new SnykAnalysisTask().handle(component, jsonObject, 200);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertNotNull(vulnerability.getCwes());
            Assert.assertEquals(1, vulnerability.getCwes().size());
            Assert.assertEquals(1333, vulnerability.getCwes().get(0).intValue());
            Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P", vulnerability.getCvssV3Vector());
            Assert.assertEquals(Severity.HIGH, vulnerability.getSeverity());
            Assert.assertNotNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getAliases());
            Assert.assertEquals(2, vulnerability.getAliases().size());
            Assert.assertEquals("CVE-2022-31129", vulnerability.getAliases().get(1).getCveId());
            Assert.assertEquals("GHSA-wc69-rhjr-hc9g", vulnerability.getAliases().get(0).getGhsaId());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("SNYK", "SNYK-JS-MOMENT-2944238", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:npm/moment"));
        Assert.assertEquals(2, vulnerableSoftware.size());
        Assert.assertEquals("2.18.0", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("2.29.4", vulnerableSoftware.get(0).getVersionEndExcluding());
    }

}
