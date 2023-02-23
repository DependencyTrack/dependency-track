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
package org.dependencytrack.tasks;

import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty;
import com.github.packageurl.PackageURL;
import org.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.persistence.CweImporter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;

public class OsvDownloadTaskTest extends PersistenceCapableTest {
    private JSONObject jsonObject;
    private final OsvAdvisoryParser parser = new OsvAdvisoryParser();
    private OsvDownloadTask task;

    @Before
    public void setUp() {
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName(),
                "Maven;DWF;Maven",
                IConfigProperty.PropertyType.STRING,
                "List of ecosystems");
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName(),
                "https://osv-vulnerabilities.storage.googleapis.com/",
                IConfigProperty.PropertyType.URL,
                "OSV Base URL");
        qm.createConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "");
        qm.createConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "");
        task = new OsvDownloadTask();
        Assert.assertNotNull(task.getEnabledEcosystems());
        Assert.assertEquals(2, task.getEnabledEcosystems().size());
    }

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
        Assert.assertNull(vulnerableSoftware.get(0).getVersionStartIncluding());
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

        // incoming vulnerability when vulnerability with same ID already exists
        prepareJsonObject("src/test/resources/unit/osv.jsons/new-GHSA-77rv-6vfw-x4gc.json");
        advisory = parser.parse(jsonObject);
        Assert.assertNotNull(advisory);
        task.updateDatasource(advisory);
        vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        Assert.assertNotNull(vulnerability);
        assertVulnerability.accept(vulnerability); // Ensure that the vulnerability was not modified
        Assert.assertEquals(1, vulnerability.getVulnerableSoftware().size());
        Assert.assertEquals("3.1.0", vulnerability.getVulnerableSoftware().get(0).getVersionStartIncluding());
        Assert.assertEquals("3.3.0", vulnerability.getVulnerableSoftware().get(0).getVersionEndExcluding());
    }

    @Test
    public void testUpdateDatasourceVulnerableVersionRanges() {
        var vs1 = new VulnerableSoftware();
        vs1.setPurlType("maven");
        vs1.setPurlNamespace("com.fasterxml.jackson.core");
        vs1.setPurlName("jackson-databind");
        vs1.setVersionStartIncluding("2.13.0");
        vs1.setVersionEndIncluding("2.13.2.0");
        vs1.setVulnerable(true);
        vs1 = qm.persist(vs1);

        var vs2 = new VulnerableSoftware();
        vs2.setPurlType("maven");
        vs2.setPurlNamespace("com.fasterxml.jackson.core");
        vs2.setPurlName("jackson-databind");
        vs2.setVersionEndIncluding("2.12.6.0");
        vs2.setVulnerable(true);
        vs2 = qm.persist(vs2);

        var vs3 = new VulnerableSoftware();
        vs3.setPurlType("maven");
        vs3.setPurlNamespace("com.fasterxml.jackson.core");
        vs3.setPurlName("jackson-databind");
        vs3.setVersionStartIncluding("1");
        vs3.setVulnerable(true);
        vs3 = qm.persist(vs3);

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("GHSA-57j2-w4cx-62h2");
        existingVuln.setSource(Vulnerability.Source.GITHUB);
        existingVuln.setVulnerableSoftware(List.of(vs1, vs2, vs3));
        existingVuln = qm.createVulnerability(existingVuln, false);
        qm.updateAffectedVersionAttribution(existingVuln, vs1, Vulnerability.Source.GITHUB);
        qm.updateAffectedVersionAttribution(existingVuln, vs2, Vulnerability.Source.GITHUB);
        qm.updateAffectedVersionAttribution(existingVuln, vs3, Vulnerability.Source.OSV);

        // Simulate OSV reporting the same affected version ranges as vs1 and vs2.
        // No vulnerable version range matching vs3, but one additional range is reported.
        // Because vs3 was attributed to OSV, the association with the vulnerability
        // should be removed in the mirroring process.
        task.updateDatasource(parser.parse(new JSONObject("""
                {
                   "id": "GHSA-57j2-w4cx-62h2",
                   "summary": "Deeply nested json in jackson-databind",
                   "details": "jackson-databind is a data-binding package for the Jackson Data Processor. jackson-databind allows a Java stack overflow exception and denial of service via a large depth of nested objects.",
                   "aliases": [
                     "CVE-2020-36518"
                   ],
                   "modified": "2022-09-22T03:50:20.996451Z",
                   "published": "2022-03-12T00:00:36Z",
                   "affected": [
                     {
                       "package": {
                         "name": "com.fasterxml.jackson.core:jackson-databind",
                         "ecosystem": "Maven",
                         "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind"
                       },
                       "ranges": [
                         {
                           "type": "ECOSYSTEM",
                           "events": [
                             {
                               "introduced": "2.13.0"
                             },
                             {
                               "fixed": "2.13.2.1"
                             }
                           ]
                         }
                       ],
                       "database_specific": {
                         "last_known_affected_version_range": "<= 2.13.2.0",
                         "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/03/GHSA-57j2-w4cx-62h2/GHSA-57j2-w4cx-62h2.json"
                       }
                     },
                     {
                       "package": {
                         "name": "com.fasterxml.jackson.core:jackson-databind",
                         "ecosystem": "Maven",
                         "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind"
                       },
                       "ranges": [
                         {
                           "type": "ECOSYSTEM",
                           "events": [
                             {
                               "introduced": "0"
                             }
                           ]
                         }
                       ],
                       "database_specific": {
                         "last_known_affected_version_range": "<= 2.12.6.0",
                         "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/03/GHSA-57j2-w4cx-62h2/GHSA-57j2-w4cx-62h2.json"
                       }
                     }
                   ],
                   "schema_version": "1.3.0",
                   "severity": [
                     {
                       "type": "CVSS_V3",
                       "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                     }
                   ]
                 }
                """)));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();

        final List<VulnerableSoftware> vsList = vuln.getVulnerableSoftware();
        assertThat(vsList).satisfiesExactlyInAnyOrder(
                // The version range that was reported by another source must be retained.
                // There must be no attribution to OSV for this range.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("2.13.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isEqualTo("2.13.2.0");
                    assertThat(vs.getVersionEndExcluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.GITHUB)
                    );
                },
                // The version range reported by both OSV and another source
                // must have attributions for both sources.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isEqualTo("2.12.6.0");
                    assertThat(vs.getVersionEndExcluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactlyInAnyOrder(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.GITHUB),
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.OSV)
                    );
                },
                // The version range newly reported by OSV must be attributed to only OSV.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("2.13.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("2.13.2.1");

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.OSV)
                    );
                }
        );
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

    @Test
    public void testGetEcosystems() {

        List<String> ecosystems = task.getEcosystems();
        Assert.assertNotNull(ecosystems);
        Assert.assertTrue(ecosystems.contains("Maven"));
    }

    @Test
    public void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromEnabledNvdSource() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-existing-nvd-vuln-CVE-2021-34552.json");

        var vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setPurlType("alpine");
        vulnerableSoftware.setPurlName("py3-pillow");
        vulnerableSoftware.setVersionStartIncluding("8.2.0");
        vulnerableSoftware.setVersionEndExcluding("8.3.0-r0");
        vulnerableSoftware.setVulnerable(true);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("CVE-2021-34552");
        existingVuln.setDescription("Initial description");
        existingVuln.setSource(Vulnerability.Source.NVD);
        existingVuln.setSeverity(Severity.CRITICAL);
        existingVuln.setVulnerableSoftware(List.of(vulnerableSoftware));
        existingVuln = qm.createVulnerability(existingVuln, false);
        qm.updateAffectedVersionAttribution(existingVuln, vulnerableSoftware, Vulnerability.Source.NVD);

        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("NVD", "CVE-2021-34552", false);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
        Assert.assertEquals(existingVuln.getDescription(), vulnerability.getDescription());

        final List<VulnerableSoftware> vsList = vulnerability.getVulnerableSoftware();
        assertThat(vsList).satisfiesExactlyInAnyOrder(
                // The version range that was reported by Github must be retained.
                // There must be no attribution to OSV for this range.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("alpine");
                    assertThat(vs.getPurlName()).isEqualTo("py3-pillow");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("8.2.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("8.3.0-r0");
                    assertThat(vs.getVersionEndIncluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vulnerability, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.NVD)
                    );
                },
                // The version range newly reported by OSV must be attributed to only OSV.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("alpine");
                    assertThat(vs.getPurlName()).isEqualTo("py3-pillow");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("8.3.0-r0");
                    assertThat(vs.getVersionEndIncluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vulnerability, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.OSV)
                    );
                }
        );
    }

    @Test
    public void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromDisabledNvdSource() throws IOException {

        ConfigProperty property = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
        property.setPropertyValue("false");
        qm.getPersistenceManager().flush();

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-existing-nvd-vuln-CVE-2021-34552.json");

        var vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setPurlType("alpine");
        vulnerableSoftware.setPurlName("py3-pillow");
        vulnerableSoftware.setVersionStartIncluding("8.2.0");
        vulnerableSoftware.setVersionEndExcluding("8.3.0-r0");
        vulnerableSoftware.setVulnerable(true);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("CVE-2021-34552");
        existingVuln.setDescription("Initial description");
        existingVuln.setSource(Vulnerability.Source.NVD);
        existingVuln.setSeverity(Severity.CRITICAL);
        existingVuln.setVulnerableSoftware(List.of(vulnerableSoftware));
        existingVuln = qm.createVulnerability(existingVuln, false);
        qm.updateAffectedVersionAttribution(existingVuln, vulnerableSoftware, Vulnerability.Source.NVD);

        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("NVD", "CVE-2021-34552", false);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(Severity.UNASSIGNED, vulnerability.getSeverity());
        Assert.assertEquals(jsonObject.getString("details"), vulnerability.getDescription());

        final List<VulnerableSoftware> vsList = vulnerability.getVulnerableSoftware();
        assertThat(vsList).satisfiesExactlyInAnyOrder(
                // The version range that was reported by Github must be retained.
                // There must be no attribution to OSV for this range.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("alpine");
                    assertThat(vs.getPurlName()).isEqualTo("py3-pillow");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("8.2.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("8.3.0-r0");
                    assertThat(vs.getVersionEndIncluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vulnerability, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.NVD)
                    );
                },
                // The version range newly reported by OSV must be attributed to only OSV.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("alpine");
                    assertThat(vs.getPurlName()).isEqualTo("py3-pillow");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("8.3.0-r0");
                    assertThat(vs.getVersionEndIncluding()).isNull();

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vulnerability, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Vulnerability.Source.OSV)
                    );
                }
        );
    }

    @Test
    public void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromEnabledGithubSource() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("GHSA-77rv-6vfw-x4gc");
        existingVuln.setSource(Vulnerability.Source.GITHUB);
        existingVuln.setSeverity(Severity.LOW);
        qm.createVulnerability(existingVuln, false);

        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", false);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(Severity.LOW, vulnerability.getSeverity());
    }

    @Test
    public void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromDisabledGithubSource() throws IOException {

        ConfigProperty property = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName());
        property.setPropertyValue("false");
        qm.getPersistenceManager().flush();

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("GHSA-77rv-6vfw-x4gc");
        existingVuln.setSource(Vulnerability.Source.GITHUB);
        existingVuln.setSeverity(Severity.LOW);
        qm.createVulnerability(existingVuln, false);

        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", false);
        Assert.assertNotNull(vulnerability);
        Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
    }

    private void prepareJsonObject(String filePath) throws IOException {
        // parse OSV json file to Advisory object
        String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
        jsonObject = new JSONObject(jsonString);
    }
}