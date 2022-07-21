/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.task;

import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.persistence.CweImporter;
import org.dependencytrack.tasks.OsvDownloadTask;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Consumer;

public class OsvDownloadTaskTest extends PersistenceCapableTest {
    private JSONObject jsonObject;
    private final OsvAdvisoryParser parser = new OsvAdvisoryParser();
    private final OsvDownloadTask task = new OsvDownloadTask();

    @Test
    public void testParseOSVJsonToAdvisoryAndSave() throws Exception {
        new CweImporter().processCweDefinitions(); // Necessary for resolving CWEs

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Assert.assertEquals(8, advisory.getAffectedPackages().size());

        // pass the mapped advisory to OSV task to update the database
        task.updateDatasource(advisory);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertNotNull(vulnerability.getCwes());
            Assert.assertEquals(1, vulnerability.getCwes().size());
            Assert.assertEquals(601, vulnerability.getCwes().get(0).intValue());
            Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", vulnerability.getCvssV3Vector());
            Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2019, 3, 14, 15, 39, 30).toInstant(ZoneOffset.UTC), vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2022, 6, 9, 7, 1, 32, 587000000).toInstant(ZoneOffset.UTC), vulnerability.getUpdated().toInstant());
            Assert.assertEquals("Skywalker, Solo", vulnerability.getCredits());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:maven/org.springframework.security.oauth/spring-security-oauth"));
        Assert.assertEquals(4, vulnerableSoftware.size());
        Assert.assertEquals("0", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("2.0.17", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("2.1.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("2.1.4", vulnerableSoftware.get(1).getVersionEndExcluding());
        Assert.assertEquals("2.2.0", vulnerableSoftware.get(2).getVersionStartIncluding());
        Assert.assertEquals("2.2.4", vulnerableSoftware.get(2).getVersionEndExcluding());
        Assert.assertEquals("2.3.0", vulnerableSoftware.get(3).getVersionStartIncluding());
        Assert.assertEquals("2.3.5", vulnerableSoftware.get(3).getVersionEndExcluding());

        // The advisory reports both spring-security-oauth and spring-security-oauth2 as affected
        vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:maven/org.springframework.security.oauth/spring-security-oauth2"));
        Assert.assertEquals(4, vulnerableSoftware.size());

        // incoming vulnerability from osv when vulnerability already exists from github
        prepareJsonObject("src/test/resources/unit/osv.jsons/new-GHSA-77rv-6vfw-x4gc.json");
        advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        task.updateDatasource(advisory);
        vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        Assert.assertNotNull(vulnerability);
        assertVulnerability.accept(vulnerability); // Ensure that the vulnerability was not modified
        Assert.assertEquals(9, vulnerability.getVulnerableSoftware().size());
        Assert.assertEquals("3.1.0", vulnerability.getVulnerableSoftware().get(8).getVersionStartIncluding());
        Assert.assertEquals("3.3.0", vulnerability.getVulnerableSoftware().get(8).getVersionEndExcluding());
    }

    @Test
    public void testParseAdvisoryToVulnerability() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Vulnerability vuln = task.mapAdvisoryToVulnerability(qm, advisory);
        Assert.assertNotNull(vuln);
        Assert.assertEquals("Skywalker, Solo", vuln.getCredits());
        Assert.assertEquals("GITHUB", vuln.getSource());
        Assert.assertEquals(Severity.CRITICAL, vuln.getSeverity());
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", vuln.getCvssV3Vector());
    }

    @Test
    public void testParseAdvisoryToVulnerabilityWithInvalidPurl() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-invalid-purl.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);
        Assert.assertNotNull(advisory);
        Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-2021-60", true);
        Assert.assertNotNull(vuln);
        Assert.assertEquals(Severity.MEDIUM, vuln.getSeverity());
        Assert.assertEquals(1, vuln.getVulnerableSoftware().size());
    }

    @Test
    public void testWithdrawnAdvisory() throws Exception {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-withdrawn.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNull(advisory);
    }

    @Test
    public void testSourceOfVulnerability() {

        String sourceTestId = "GHSA-77rv-6vfw-x4gc";
        Vulnerability.Source source = task.extractSource(sourceTestId);
        Assert.assertNotNull(source);
        Assert.assertEquals(Vulnerability.Source.GITHUB, source);

        sourceTestId = "CVE-2022-tyhg";
        source = task.extractSource(sourceTestId);
        Assert.assertNotNull(source);
        Assert.assertEquals(Vulnerability.Source.NVD, source);

        sourceTestId = "anyOther-2022-tyhg";
        source = task.extractSource(sourceTestId);
        Assert.assertNotNull(source);
        Assert.assertEquals(Vulnerability.Source.OSV, source);
    }

    @Test
    public void testCalculateOSVSeverity() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Severity severity = task.calculateOSVSeverity(advisory);
        Assert.assertEquals(Severity.CRITICAL, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-severity-test-ecosystem-cvss.json");
        advisory = parser.parse(jsonObject);
        severity = task.calculateOSVSeverity(advisory);
        Assert.assertEquals(Severity.CRITICAL, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-severity-test-ecosystem.json");
        advisory = parser.parse(jsonObject);
        severity = task.calculateOSVSeverity(advisory);
        Assert.assertEquals(Severity.MEDIUM, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-vulnerability-no-range.json");
        advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        severity = task.calculateOSVSeverity(advisory);
        Assert.assertEquals(Severity.UNASSIGNED, severity);
    }

    @Test
    public void testFindExistingClashingVulnerability() throws IOException {

        // insert a vulnerability in database
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        // tests for incoming vulnerabilities if it or its alias already exists
        prepareJsonObject("src/test/resources/unit/osv.jsons/new-GHSA-77rv-6vfw-x4gc.json");
        advisory = parser.parse(jsonObject);
        Vulnerability vulnerabilityIncoming = task.mapAdvisoryToVulnerability(qm, advisory);
        Vulnerability existingVuln = task.findExistingClashingVulnerability(qm, vulnerabilityIncoming, advisory);
        Assert.assertNotNull(existingVuln);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-vulnerability-no-range.json");
        advisory = parser.parse(jsonObject);
        vulnerabilityIncoming = task.mapAdvisoryToVulnerability(qm, advisory);
        existingVuln = task.findExistingClashingVulnerability(qm, vulnerabilityIncoming, advisory);
        Assert.assertNull(existingVuln);

        advisory.addAlias("GHSA-77rv-6vfw-x4gc");
        vulnerabilityIncoming = task.mapAdvisoryToVulnerability(qm, advisory);
        existingVuln = task.findExistingClashingVulnerability(qm, vulnerabilityIncoming, advisory);
        Assert.assertNotNull(existingVuln);
    }

    @Test
    public void testCommitHashRangesAndVersions() throws IOException {

        // insert a vulnerability in database
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-git-commit-hash-ranges.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("OSV", "OSV-2021-1820", true);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(22, vulnerability.getVulnerableSoftware().size());
        Assert.assertEquals(Severity.MEDIUM, vulnerability.getSeverity());
    }

    private void prepareJsonObject(String filePath) throws IOException {
        // parse OSV json file to Advisory object
        String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
        jsonObject = new JSONObject(jsonString);
    }
}