package org.dependencytrack.tasks.scanners;

import alpine.model.IConfigProperty;
import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.snyk.SnykParser;
import org.dependencytrack.persistence.CweImporter;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_API_USERNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_CVSS_SOURCE;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;

public class SnykAnalysisTaskTest extends PersistenceCapableTest {

    private JSONObject jsonObject;

    private SnykAnalysisTask task = new SnykAnalysisTask();

    private SnykParser parser = new SnykParser();

    @Test
    public void testParseSnykJsonToAdvisoryAndSave() throws Exception {
        new CweImporter().processCweDefinitions(); // Necessary for resolving CWEs

        prepareJsonObject("src/test/resources/unit/snyk.jsons/snyk-vuln.json");
        Component component = new Component();
        component.setPurl("pkg:npm/moment@2.24.0");
        component.setUuid(UUID.randomUUID());
        component.setName("test-snyk");

        task.handle(component, jsonObject, 200);

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

    @Test
    public void testParseVersionRanges() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range0");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(1, vulnerableSoftwares.size());

        VulnerableSoftware vs = vulnerableSoftwares.get(0);
        Assert.assertEquals("2.13.0", vs.getVersionStartIncluding());
        Assert.assertEquals("2.13.2.1", vs.getVersionEndExcluding());
    }

    @Test
    public void testParseVersionRangesStar() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range2");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(0, vulnerableSoftwares.size());
    }

    @Test
    public void testParseVersionIndefiniteRanges() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range1");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(0, vulnerableSoftwares.size());
    }
    @Test
    public void testParseSeveritiesNvd() throws IOException {

        // By default NVD is first priority for CVSS, no need to set config property.
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities2");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities5");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
    }

    @Test
    public void testParseSeveritiesSnyk() throws IOException {

        qm.createConfigProperty(SCANNER_SNYK_CVSS_SOURCE.getGroupName(),
                SCANNER_SNYK_CVSS_SOURCE.getPropertyName(),
                "SNYK",
                IConfigProperty.PropertyType.STRING,
                "First priority source for cvss calculation");

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities3");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities4");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
    }

    @Test
    public void testSelectCvssObjectBasedOnSource() throws IOException {
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));

        severities = jsonObject.optJSONArray("severities4");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));

        severities = jsonObject.optJSONArray("severities2");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P", cvss.optString("vector"));
        severities = jsonObject.optJSONArray("severities3");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));
    }

    @Test
    public void testGetSnykCvssConfig() {
        qm.createConfigProperty(SCANNER_SNYK_API_TOKEN.getGroupName(),
                SCANNER_SNYK_API_TOKEN.getPropertyName(),
                "token",
                IConfigProperty.PropertyType.STRING,
                "token");
        qm.createConfigProperty(SCANNER_OSSINDEX_API_USERNAME.getGroupName(),
                SCANNER_OSSINDEX_API_USERNAME.getPropertyName(),
                "username",
                IConfigProperty.PropertyType.STRING,
                "username");

        String config = parser.getSnykCvssConfig(SCANNER_SNYK_CVSS_SOURCE);
        Assert.assertNotNull(config);
        Assert.assertEquals("NVD", config);
        config = parser.getSnykCvssConfig(SCANNER_SNYK_ENABLED);
        Assert.assertNotNull(config);
        Assert.assertEquals("false", config);
        config = parser.getSnykCvssConfig(SCANNER_SNYK_API_TOKEN);
        Assert.assertNotNull(config);
        Assert.assertEquals("token", config);
        config = parser.getSnykCvssConfig(SCANNER_OSSINDEX_API_USERNAME);
        Assert.assertNotNull(config);
        Assert.assertEquals("username", config);
    }

    private void prepareJsonObject(String filePath) throws IOException {
        // parse json file to Advisory object
        String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
        jsonObject = new JSONObject(jsonString);
    }
}
