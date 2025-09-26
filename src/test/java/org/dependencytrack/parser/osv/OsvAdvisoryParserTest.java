package org.dependencytrack.parser.osv;

import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

class OsvAdvisoryParserTest {

    OsvAdvisoryParser parser = new OsvAdvisoryParser();

    @Test
    void testTrimSummary() {

        String osvLongSummary = "In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.";
        String trimmedSummary = parser.trimSummary(osvLongSummary);
        Assertions.assertNotNull(trimmedSummary);
        Assertions.assertEquals(255, trimmedSummary.length());
        Assertions.assertEquals("In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not ne..", trimmedSummary);

        osvLongSummary = "I'm a short Summary";
        trimmedSummary = parser.trimSummary(osvLongSummary);
        Assertions.assertNotNull(trimmedSummary);
        Assertions.assertEquals("I'm a short Summary", trimmedSummary);

        osvLongSummary = null;
        trimmedSummary = parser.trimSummary(osvLongSummary);
        Assertions.assertNull(trimmedSummary);
    }

    @Test
    void testVulnerabilityRangeEmpty() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-no-range.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(0));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(1, affectedPackages.size());
    }

    @Test
    void testVulnerabilityRangeSingle() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(1));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(1, affectedPackages.size());
        OsvAffectedPackage affectedPackage = affectedPackages.get(0);
        Assertions.assertEquals("pkg:maven/org.springframework.security.oauth/spring-security-oauth", affectedPackage.getPurl());
        Assertions.assertEquals("0", affectedPackage.getLowerVersionRange());
        Assertions.assertEquals("2.0.17", affectedPackage.getUpperVersionRangeExcluding());
        Assertions.assertEquals("Maven", affectedPackage.getPackageEcosystem());

    }

    @Test
    void testVulnerabilityRangeMultiple() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray affected = jsonObject.optJSONArray("affected");

        // range test full pairs
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(2));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(3, affectedPackages.size());
        Assertions.assertEquals("1", affectedPackages.get(0).getLowerVersionRange());
        Assertions.assertEquals("2", affectedPackages.get(0).getUpperVersionRangeExcluding());
        Assertions.assertEquals("3", affectedPackages.get(1).getLowerVersionRange());
        Assertions.assertEquals("4", affectedPackages.get(1).getUpperVersionRangeExcluding());

        // range test half pairs
        affectedPackages = parser.parseAffectedPackageRange(affected.getJSONObject(3));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(2, affectedPackages.size());
        Assertions.assertEquals("3", affectedPackages.get(0).getLowerVersionRange());
        Assertions.assertEquals("4", affectedPackages.get(1).getLowerVersionRange());
        Assertions.assertEquals("5", affectedPackages.get(1).getUpperVersionRangeExcluding());
    }

    @Test
    void testVulnerabilityRangeTypes() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-vulnerability-with-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        final JSONArray vulnerabilities = jsonObject.optJSONArray("affected");

        // type last_affected
        List<OsvAffectedPackage> affectedPackages = parser.parseAffectedPackageRange(vulnerabilities.getJSONObject(5));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(1, affectedPackages.size());
        Assertions.assertEquals("10", affectedPackages.get(0).getLowerVersionRange());
        Assertions.assertEquals("13", affectedPackages.get(0).getUpperVersionRangeExcluding());

        // type last_affected
        affectedPackages = parser.parseAffectedPackageRange(vulnerabilities.getJSONObject(6));
        Assertions.assertNotNull(affectedPackages);
        Assertions.assertEquals(1, affectedPackages.size());
        Assertions.assertEquals("10", affectedPackages.get(0).getLowerVersionRange());
        Assertions.assertEquals(null, affectedPackages.get(0).getUpperVersionRangeExcluding());
        Assertions.assertEquals("29.0", affectedPackages.get(0).getUpperVersionRangeIncluding());

    }

    @Test
    void testParseOSVJson() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        Assertions.assertEquals("GHSA-77rv-6vfw-x4gc", advisory.getId());
        Assertions.assertEquals("LOW", advisory.getSeverity());
        Assertions.assertEquals(1, advisory.getCweIds().size());
        Assertions.assertEquals(6, advisory.getReferences().size());
        Assertions.assertEquals(2, advisory.getCredits().size());
        Assertions.assertEquals(8, advisory.getAffectedPackages().size());
        Assertions.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", advisory.getCvssV3Vector());
        Assertions.assertEquals("CVE-2019-3778", advisory.getAliases().get(0));
        Assertions.assertEquals("2022-06-09T07:01:32.587163Z", advisory.getModified().toString());
    }

    @Test
    void testCommitHashRanges() throws IOException {

        String jsonFile = "src/test/resources/unit/osv.jsons/osv-git-commit-hash-ranges.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        Assertions.assertEquals("OSV-2021-1820", advisory.getId());
        Assertions.assertEquals(22, advisory.getAffectedPackages().size());
        Assertions.assertEquals("4.4.0", advisory.getAffectedPackages().get(0).getVersion());
    }

    @Test
        // https://github.com/DependencyTrack/dependency-track/issues/3185
    void testIssue3185() throws Exception {
        String jsonFile = "src/test/resources/unit/osv.jsons/osv-CVE-2016-10012.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
    }

    @Test
        // https://github.com/DependencyTrack/dependency-track/issues/5105
    void testIssue5105() throws Exception {
        String jsonFile = "src/test/resources/unit/osv.jsons/osv-UBUNTU-CVE-2025-6297.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
    }
}
