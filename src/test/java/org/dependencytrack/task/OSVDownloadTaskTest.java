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

import kong.unirest.json.JSONObject;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.osv.GoogleOSVAdvisoryParser;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.OSVDownloadTask;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class OSVDownloadTaskTest extends PersistenceCapableTest {
    private JSONObject jsonObject;
    private final GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();
    private final OSVDownloadTask task = new OSVDownloadTask();

    @Test
    public void testParseOSVJsonToAdvisoryAndSave() throws Exception {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OSVAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Assert.assertEquals(8, advisory.getVulnerabilities().size());

        // pass the mapped advisory to OSV task to update the database
        task.updateDatasource(advisory);
        var qm = new QueryManager();

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        Assert.assertNotNull(vulnerability);

        var vulnerableSoftware = qm.getVulnerableSoftwareByPurl("pkg:maven/org.springframework.security.oauth/spring-security-oauth", "2.0.17", "0");
        Assert.assertNotNull(vulnerableSoftware);
        Assert.assertEquals("maven", vulnerableSoftware.getPurlType());
        Assert.assertEquals("org.springframework.security.oauth", vulnerableSoftware.getPurlNamespace());
        Assert.assertEquals("spring-security-oauth", vulnerableSoftware.getPurlName());
        Assert.assertEquals("0", vulnerableSoftware.getVersionStartIncluding());
        Assert.assertEquals("2.0.17", vulnerableSoftware.getVersionEndExcluding());

        vulnerableSoftware = qm.getVulnerableSoftwareByPurl("pkg:maven/org.springframework.security.oauth/spring-security-oauth", "2.1.4", "2.1.0");
        Assert.assertNotNull(vulnerableSoftware);
        Assert.assertEquals("2.1.0", vulnerableSoftware.getVersionStartIncluding());
        Assert.assertEquals("2.1.4", vulnerableSoftware.getVersionEndExcluding());

        // incoming vulnerability from osv when vulnerability already exists from github
        prepareJsonObject("src/test/resources/unit/osv.jsons/new-GHSA-77rv-6vfw-x4gc.json");
        advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        task.updateDatasource(advisory);
        vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(9, vulnerability.getVulnerableSoftware().size());
        Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
    }

    @Test
    public void testParseAdvisoryToVulnerability() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OSVAdvisory advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        Vulnerability vuln = task.mapAdvisoryToVulnerability(new QueryManager(), advisory);
        Assert.assertNotNull(vuln);
        Assert.assertEquals("Skywalker, Solo", vuln.getCredits());
        Assert.assertEquals("GITHUB", vuln.getSource());
        Assert.assertEquals(Severity.CRITICAL, vuln.getSeverity());
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", vuln.getCvssV3Vector());
    }

    @Test
    public void testWithdrawnAdvisory() throws Exception {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-withdrawn.json");
        OSVAdvisory advisory = parser.parse(jsonObject);
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
        Assert.assertEquals(Vulnerability.Source.GOOGLE, source);
    }

    @Test
    public void testCalculateOSVSeverity() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OSVAdvisory advisory = parser.parse(jsonObject);
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
        OSVAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);
        var qm = new QueryManager();

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
        OSVAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);
        var qm = new QueryManager();

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GOOGLE", "OSV-2021-1820", true);
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