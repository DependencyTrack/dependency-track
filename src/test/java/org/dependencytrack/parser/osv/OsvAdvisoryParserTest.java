package org.dependencytrack.parser.osv;

import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class OsvAdvisoryParserTest {

    OsvAdvisoryParser parser = new OsvAdvisoryParser();

    @Test
    public void testTrimSummary() {

        String osvLongSummary = "In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.";
        String trimmedSummary = parser.trimSummary(osvLongSummary);
        Assert.assertNotNull(trimmedSummary);
        Assert.assertEquals(255, trimmedSummary.length());
        Assert.assertEquals("In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not ne..", trimmedSummary);

        osvLongSummary = "I'm a short Summary";
        trimmedSummary = parser.trimSummary(osvLongSummary);
        Assert.assertNotNull(trimmedSummary);
        Assert.assertEquals("I'm a short Summary", trimmedSummary);

        osvLongSummary = null;
        trimmedSummary = parser.trimSummary(osvLongSummary);
        Assert.assertNull(trimmedSummary);
    }

    @Test
    public void testVulnerabilityRangeEmpty() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-no-range.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(0));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(1, affectedPackages.size());
    }

    @Test
    public void testVulnerabilityRangeSingle() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(1));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(1, affectedPackages.size());
        OsvAffectedPackage affectedPackage = affectedPackages.get(0);
        Assert.assertEquals("pkg:maven/org.springframework.security.oauth/spring-security-oauth", affectedPackage.getPurl());
        Assert.assertEquals("0", affectedPackage.getLowerVersionRange());
        Assert.assertEquals("2.0.17", affectedPackage.getUpperVersionRangeExcluding());
        Assert.assertEquals("Maven", affectedPackage.getPackageEcosystem());

    }

    @Test
    public void testVulnerabilityRangeMultiple() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");

        // range test full pairs
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(2));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(3, affectedPackages.size());
        Assert.assertEquals("1", affectedPackages.get(0).getLowerVersionRange());
        Assert.assertEquals("2", affectedPackages.get(0).getUpperVersionRangeExcluding());
        Assert.assertEquals("3", affectedPackages.get(1).getLowerVersionRange());
        Assert.assertEquals("4", affectedPackages.get(1).getUpperVersionRangeExcluding());

        // range test half pairs
        affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(3));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(2, affectedPackages.size());
        Assert.assertEquals("3", affectedPackages.get(0).getLowerVersionRange());
        Assert.assertEquals("4", affectedPackages.get(1).getLowerVersionRange());
        Assert.assertEquals("5", affectedPackages.get(1).getUpperVersionRangeExcluding());
    }

    @Test
    public void testVulnerabilityRangeTypes() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray vulnerabilities = jsonObject.optJSONArray("affected");

        // type last_affected
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(vulnerabilities.getJSONObject(5));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(1, affectedPackages.size());
        Assert.assertEquals("10", affectedPackages.get(0).getLowerVersionRange());
        Assert.assertEquals("13", affectedPackages.get(0).getUpperVersionRangeExcluding());

        // type last_affected
        affectedPackages = parser.parseAffectedPackageRange(vulnerabilities.getJSONObject(6));
        Assert.assertNotNull(affectedPackages);
        Assert.assertEquals(1, affectedPackages.size());
        Assert.assertEquals("10", affectedPackages.get(0).getLowerVersionRange());
        Assert.assertEquals(null, affectedPackages.get(0).getUpperVersionRangeExcluding());
        Assert.assertEquals("29.0", affectedPackages.get(0).getUpperVersionRangeIncluding());

    }

    @Test
    public void testParseOSVJson() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Assert.assertEquals("GHSA-77rv-6vfw-x4gc", advisory.getId());
        Assert.assertEquals("LOW", advisory.getSeverity());
        Assert.assertEquals(1, advisory.getCweIds().size());
        Assert.assertEquals(6, advisory.getReferences().size());
        Assert.assertEquals(2, advisory.getCredits().size());
        Assert.assertEquals(8, advisory.getAffectedPackages().size());
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", advisory.getCvssV3Vector());
        Assert.assertEquals("CVE-2019-3778", advisory.getAliases().get(0));
        Assert.assertEquals("2022-06-09T07:01:32.587163Z", advisory.getModified().toString());
    }

    @Test
    public void testCommitHashRanges() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-git-commit-hash-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Assert.assertEquals("OSV-2021-1820", advisory.getId());
        Assert.assertEquals(22, advisory.getAffectedPackages().size());
        Assert.assertEquals("4.4.0", advisory.getAffectedPackages().get(0).getVersion());
    }
}
