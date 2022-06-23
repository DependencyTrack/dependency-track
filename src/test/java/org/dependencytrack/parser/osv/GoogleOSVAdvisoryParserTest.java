package org.dependencytrack.parser.osv;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.parser.osv.model.OSVVulnerability;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class GoogleOSVAdvisoryParserTest {

    GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();

    @Test
    public void testTrimSummary() {

        String osvLongSummary = "In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.";
        String trimmedSummary = parser.trimSummary(osvLongSummary);
        Assert.assertNotNull(trimmedSummary);
        Assert.assertEquals(trimmedSummary.length(), 255);
    }

    @Test
    public void testVulnerabilityRangeEmpty() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray vulnerabilities = jsonObject.optJSONArray("affected");
        List<OSVVulnerability> osvVulnerabilityList = parser.parseVulnerabilityRange(vulnerabilities.getJSONObject(0));
        Assert.assertNotNull(osvVulnerabilityList);
        Assert.assertEquals(osvVulnerabilityList.size(), 0);
    }

    @Test
    public void testVulnerabilityRangeSingle() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray vulnerabilities = jsonObject.optJSONArray("affected");
        List<OSVVulnerability> osvVulnerabilityList = parser.parseVulnerabilityRange(vulnerabilities.getJSONObject(1));
        Assert.assertNotNull(osvVulnerabilityList);
        Assert.assertEquals(osvVulnerabilityList.size(), 1);
        OSVVulnerability vuln = osvVulnerabilityList.get(0);
        Assert.assertEquals(vuln.getPurl(), "pkg:maven/org.springframework.security.oauth/spring-security-oauth");
        Assert.assertEquals(vuln.getLowerVersionRange(), "0");
        Assert.assertEquals(vuln.getUpperVersionRange(), "2.0.17");
        Assert.assertEquals(vuln.getPackageEcosystem(), "Maven");

    }

    @Test
    public void testVulnerabilityRangeMultiple() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray vulnerabilities = jsonObject.optJSONArray("affected");

        // range test full pairs
        List<OSVVulnerability> osvVulnerabilityList = parser.parseVulnerabilityRange(vulnerabilities.getJSONObject(2));
        Assert.assertNotNull(osvVulnerabilityList);
        Assert.assertEquals(osvVulnerabilityList.size(), 2);
        Assert.assertEquals(osvVulnerabilityList.get(0).getLowerVersionRange(), "1");
        Assert.assertEquals(osvVulnerabilityList.get(0).getUpperVersionRange(), "2");
        Assert.assertEquals(osvVulnerabilityList.get(1).getLowerVersionRange(), "3");
        Assert.assertEquals(osvVulnerabilityList.get(1).getUpperVersionRange(), "4");

        // range test half pairs
        osvVulnerabilityList = parser.parseVulnerabilityRange(vulnerabilities.getJSONObject(3));
        Assert.assertNotNull(osvVulnerabilityList);
        Assert.assertEquals(osvVulnerabilityList.size(), 3);
        Assert.assertEquals(osvVulnerabilityList.get(0).getLowerVersionRange(), null);
        Assert.assertEquals(osvVulnerabilityList.get(0).getUpperVersionRange(), "2");
        Assert.assertEquals(osvVulnerabilityList.get(1).getLowerVersionRange(), "3");
        Assert.assertEquals(osvVulnerabilityList.get(1).getUpperVersionRange(), null);
        Assert.assertEquals(osvVulnerabilityList.get(2).getLowerVersionRange(), "4");
        Assert.assertEquals(osvVulnerabilityList.get(2).getUpperVersionRange(), "5");
    }

    @Test
    public void testParseOSVJson() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OSVAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Assert.assertEquals(advisory.getId(), "GHSA-77rv-6vfw-x4gc");
        Assert.assertEquals(advisory.getSeverity(), "CRITICAL");
        Assert.assertEquals(advisory.getCweIds().size(), 1);
        Assert.assertEquals(advisory.getReferences().size(), 6);
        Assert.assertEquals(advisory.getCredits().size(), 2);
        Assert.assertEquals(advisory.getVulnerabilities().size(), 8);
        Assert.assertEquals(advisory.getCvssV3Vector(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        Assert.assertEquals(advisory.getAliases().get(0), "CVE-2019-3778");
        Assert.assertEquals(advisory.getModified().toString(), "2022-06-09T07:01:32.587163Z");
    }
}
