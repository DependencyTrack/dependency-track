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
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;

@WireMockTest
class OsvDownloadTaskTest extends PersistenceCapableTest {
    private JSONObject jsonObject;
    private final OsvAdvisoryParser parser = new OsvAdvisoryParser();

    @BeforeEach
    public void setUp(WireMockRuntimeInfo wmRuntimeInfo) {
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName(),
                "Maven;DWF;Maven",
                IConfigProperty.PropertyType.STRING,
                "List of ecosystems");
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName(),
                wmRuntimeInfo.getHttpBaseUrl(),
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
    }

    @Test
    void testFullUpdate() throws Exception {
        final byte[] zippedOsvFileBytes = zipResources(new String[]{
                "/unit/osv.jsons/osv-GHSA-7qwv-cwgj-c8rj.json",
                "/unit/osv.jsons/osv-GHSA-p836-389h-j692.json",
                "/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json"
        });

        stubFor(get(urlPathEqualTo("/Maven/all.zip"))
                .willReturn(aResponse()
                        .withBody(zippedOsvFileBytes)));

        final Path mirrorDirPath = Files.createTempDirectory(null);
        mirrorDirPath.toFile().deleteOnExit();

        new OsvDownloadTask(mirrorDirPath).inform(new OsvMirrorEvent());

        assertThat(mirrorDirPath.resolve("google-osv-Maven.zip")).exists();
        assertThat(mirrorDirPath.resolve("google-osv-Maven.zip.ts")).exists();
        assertThat(mirrorDirPath.resolve("google-osv-Maven-modified.csv.ts")).exists();

        final List<Vulnerability> vulns = qm.getVulnerabilities().getList(Vulnerability.class);
        assertThat(vulns).satisfiesExactlyInAnyOrder(
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("GHSA-7qwv-cwgj-c8rj");
                    assertThat(vuln.getSource()).isEqualTo("GITHUB");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            ActionForm in Apache Software Foundation (ASF) Struts before 1.2.9 with BeanUtils 1.7 \
                            allows remote attackers to cause a denial of service via a multipart/form-data encoded \
                            form with a parameter name that references the public getMultipartRequestHandler method, \
                            which provides further access to elements in the CommonsMultipartRequestHandler \
                            implementation and BeanUtils.""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://nvd.nist.gov/vuln/detail/CVE-2006-1547](https://nvd.nist.gov/vuln/detail/CVE-2006-1547)
                            * [https://exchange.xforce.ibmcloud.com/vulnerabilities/25613](https://exchange.xforce.ibmcloud.com/vulnerabilities/25613)
                            * [https://github.com/apache/struts](https://github.com/apache/struts)
                            * [https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2006-1547](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2006-1547)
                            * [http://issues.apache.org/bugzilla/show_bug.cgi?id=38534](http://issues.apache.org/bugzilla/show_bug.cgi?id=38534)
                            * [http://lists.suse.com/archive/suse-security-announce/2006-May/0004.html](http://lists.suse.com/archive/suse-security-announce/2006-May/0004.html)
                            * [http://secunia.com/advisories/19493](http://secunia.com/advisories/19493)
                            * [http://secunia.com/advisories/20117](http://secunia.com/advisories/20117)
                            * [http://securitytracker.com/id?1015856](http://securitytracker.com/id?1015856)
                            * [http://struts.apache.org/struts-doc-1.2.9/userGuide/release-notes.html](http://struts.apache.org/struts-doc-1.2.9/userGuide/release-notes.html)""");
                    assertThat(vuln.getPublished()).isCloseTo("2022-05-01T06:50:42Z", 1000);
                    assertThat(vuln.getUpdated()).isCloseTo("2025-10-22T19:41:45.146Z", 1000);
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.HIGH);
                    assertThat(vuln.getCwes().get(0)).isEqualTo(20);
                    assertThat(vuln.getCwes().get(1)).isEqualTo(749);
                },
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("GHSA-p836-389h-j692");
                    assertThat(vuln.getSource()).isEqualTo("GITHUB");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" \
                            feature, allows remote attackers to execute arbitrary code or bypass intended access \
                            restrictions via an unspecified request parameter.""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://nvd.nist.gov/vuln/detail/CVE-2016-4437](https://nvd.nist.gov/vuln/detail/CVE-2016-4437)
                            * [https://lists.apache.org/thread.html/ef3a800c7d727a00e04b78e2f06c5cd8960f09ca28c9b69d94c3c4c4%40%3Cannouncements.aurora.apache.org%3E](https://lists.apache.org/thread.html/ef3a800c7d727a00e04b78e2f06c5cd8960f09ca28c9b69d94c3c4c4%40%3Cannouncements.aurora.apache.org%3E)
                            * [https://lists.apache.org/thread.html/ef3a800c7d727a00e04b78e2f06c5cd8960f09ca28c9b69d94c3c4c4@%3Cannouncements.aurora.apache.org%3E](https://lists.apache.org/thread.html/ef3a800c7d727a00e04b78e2f06c5cd8960f09ca28c9b69d94c3c4c4@%3Cannouncements.aurora.apache.org%3E)
                            * [https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2016-4437](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2016-4437)
                            * [http://packetstormsecurity.com/files/137310/Apache-Shiro-1.2.4-Information-Disclosure.html](http://packetstormsecurity.com/files/137310/Apache-Shiro-1.2.4-Information-Disclosure.html)
                            * [http://packetstormsecurity.com/files/157497/Apache-Shiro-1.2.4-Remote-Code-Execution.html](http://packetstormsecurity.com/files/157497/Apache-Shiro-1.2.4-Remote-Code-Execution.html)
                            * [http://rhn.redhat.com/errata/RHSA-2016-2035.html](http://rhn.redhat.com/errata/RHSA-2016-2035.html)
                            * [http://rhn.redhat.com/errata/RHSA-2016-2036.html](http://rhn.redhat.com/errata/RHSA-2016-2036.html)
                            * [http://www.securityfocus.com/archive/1/538570/100/0/threaded](http://www.securityfocus.com/archive/1/538570/100/0/threaded)
                            * [http://www.securityfocus.com/bid/91024](http://www.securityfocus.com/bid/91024)""");
                    assertThat(vuln.getPublished()).isCloseTo("2022-05-14T02:46:17Z", 1000);
                    assertThat(vuln.getUpdated()).isCloseTo("2025-10-22T19:25:56.524Z", 1000);
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.CRITICAL);
                    assertThat(vuln.getCwes().get(0)).isEqualTo(284);
                    assertThat(vuln.getCwes().get(1)).isEqualTo(321);
                },
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("GHSA-77rv-6vfw-x4gc");
                    assertThat(vuln.getSource()).isEqualTo("GITHUB");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 \
                            prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be \
                            susceptible to an open redirector attack that can leak an authorization code.
                            
                            A malicious user or attacker can craft a request to the authorization endpoint using \
                            the authorization code grant type, and specify a manipulated redirection URI via the \
                            "redirect_uri" parameter. This can cause the authorization server to redirect the \
                            resource owner user-agent to a URI under the control of the attacker with the leaked \
                            authorization code.
                            
                            This vulnerability exposes applications that meet all of the following requirements: \
                            Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses \
                            the DefaultRedirectResolver in the AuthorizationEndpoint.\s
                            
                            This vulnerability does not expose applications that: Act in the role of an Authorization \
                            Server and uses a different RedirectResolver implementation other than \
                            DefaultRedirectResolver, act in the role of a Resource Server only \
                            (e.g. @EnableResourceServer), act in the role of a Client only \
                            (e.g. @EnableOAuthClient).""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://nvd.nist.gov/vuln/detail/CVE-2019-3778](https://nvd.nist.gov/vuln/detail/CVE-2019-3778)
                            * [https://github.com/advisories/GHSA-77rv-6vfw-x4gc](https://github.com/advisories/GHSA-77rv-6vfw-x4gc)
                            * [https://pivotal.io/security/cve-2019-3778](https://pivotal.io/security/cve-2019-3778)
                            * [https://www.oracle.com/security-alerts/cpujan2021.html](https://www.oracle.com/security-alerts/cpujan2021.html)
                            * [http://packetstormsecurity.com/files/153299/Spring-Security-OAuth-2.3-Open-Redirection.html](http://packetstormsecurity.com/files/153299/Spring-Security-OAuth-2.3-Open-Redirection.html)
                            * [http://www.securityfocus.com/bid/107153](http://www.securityfocus.com/bid/107153)""");
                    assertThat(vuln.getPublished()).isCloseTo("2019-03-14T15:39:30Z", 1000);
                    assertThat(vuln.getUpdated()).isCloseTo("2022-06-09T07:01:32.587Z", 1000);
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.CRITICAL);
                    assertThat(vuln.getCwes().get(0)).isEqualTo(601);
                }
        );
    }

    @Test
    void testIncrementalUpdate() throws Exception {
        stubFor(get(urlPathEqualTo("/Maven/modified_id.csv"))
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/osv.jsons/google-osv-Maven-modified.csv"))));
        stubFor(get(urlPathEqualTo("/Maven/GHSA-j7mw-7crr-658v.json"))
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/osv.jsons/osv-GHSA-j7mw-7crr-658v.json"))));

        final Path mirrorDirPath = Files.createTempDirectory(null);
        mirrorDirPath.toFile().deleteOnExit();

        // Mock .zip file and .ts files to trigger an incremental update
        final Path tempMockZipFile = mirrorDirPath.resolve("google-osv-Maven.zip");
        Files.writeString(tempMockZipFile, "------fake-zip-data------");
        final Path tempMockZipTsFile = mirrorDirPath.resolve("google-osv-Maven.zip.ts");
        Files.writeString(tempMockZipTsFile, "2025-10-22T17:35:28Z", StandardCharsets.UTF_8);
        final Path tempMockCsvTsFile = mirrorDirPath.resolve("google-osv-Maven-modified.csv.ts");
        Files.writeString(tempMockCsvTsFile, "2025-10-22T17:35:28Z", StandardCharsets.UTF_8);

        // Fixed clock for Instant.now() in the OsvDownloadTask, such that the incremental update will be correctly triggered in this test
        final Instant instant = Instant.parse("2025-10-23T17:00:00Z");
        final Clock clock = Clock.fixed(instant, ZoneOffset.UTC);

        new OsvDownloadTask(mirrorDirPath, clock).inform(new OsvMirrorEvent());

        assertThat(mirrorDirPath.resolve("google-osv-Maven-modified.csv")).exists();
        final List<Vulnerability> vulns = qm.getVulnerabilities().getList(Vulnerability.class);
        assertThat(vulns).hasSize(1);
        final Vulnerability vuln = vulns.getFirst();
        assertThat(vuln.getVulnId()).isEqualTo("GHSA-j7mw-7crr-658v");
        assertThat(vuln.getSource()).isEqualTo("GITHUB");
        assertThat(vuln.getDescription()).isEqualTo("""
                The RichFaces Framework 3.X through 3.3.4 is vulnerable to Expression Language (EL) \
                injection via the UserResource resource. A remote, unauthenticated attacker could exploit \
                this to execute arbitrary code using a chain of java serialized objects via \
                `org.ajax4jsf.resource.UserResource$UriData`.""");
        assertThat(vuln.getReferences()).isEqualTo("""
                * [https://nvd.nist.gov/vuln/detail/CVE-2018-14667](https://nvd.nist.gov/vuln/detail/CVE-2018-14667)
                * [https://github.com/richfaces/richfaces/commit/1372eb716c1a215a5af124198f21bde33fafad06](https://github.com/richfaces/richfaces/commit/1372eb716c1a215a5af124198f21bde33fafad06)
                * [https://access.redhat.com/errata/RHSA-2018:3517](https://access.redhat.com/errata/RHSA-2018:3517)
                * [https://access.redhat.com/errata/RHSA-2018:3518](https://access.redhat.com/errata/RHSA-2018:3518)
                * [https://access.redhat.com/errata/RHSA-2018:3519](https://access.redhat.com/errata/RHSA-2018:3519)
                * [https://access.redhat.com/errata/RHSA-2018:3581](https://access.redhat.com/errata/RHSA-2018:3581)
                * [https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14667](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14667)
                * [https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2018-14667](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2018-14667)
                * [http://packetstormsecurity.com/files/156663/Richsploit-RichFaces-Exploitation-Toolkit.html](http://packetstormsecurity.com/files/156663/Richsploit-RichFaces-Exploitation-Toolkit.html)
                * [http://seclists.org/fulldisclosure/2020/Mar/21](http://seclists.org/fulldisclosure/2020/Mar/21)""");
        assertThat(vuln.getPublished()).isCloseTo("2022-05-13T01:17:53Z", 1000);
        assertThat(vuln.getUpdated()).isCloseTo("2025-10-22T17:36:28Z", 1000);
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H");
        assertThat(vuln.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(vuln.getCwes().get(0)).isEqualTo(94);
        assertThat(vuln.getVulnerableSoftware()).hasSize(1);
        final VulnerableSoftware vs = vuln.getVulnerableSoftware().get(0);
        assertThat(vs.getPurl()).isEqualTo("pkg:maven/org.richfaces/richfaces-core");
        assertThat(vs.getVersionEndExcluding()).isEqualTo("3.3.4");
    }

    private byte[] zipResources(final String[] resourcePaths) throws Exception {
        final var byteArrayOutputStream = new ByteArrayOutputStream();
        try (final var zipOutputStream = new ZipOutputStream(byteArrayOutputStream)) {
            for (String resource : resourcePaths) {
                zipOutputStream.putNextEntry(new ZipEntry(new File(resource).getName()));
                zipOutputStream.write(resourceToByteArray(resource));
                zipOutputStream.closeEntry();
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    @Test
    void testParseOSVJsonToAdvisoryAndSave() throws Exception {
        // Enable alias synchronization
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyType(),
                null
        );

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        Assertions.assertEquals(8, advisory.getAffectedPackages().size());

        // pass the mapped advisory to OSV task to update the database
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assertions.assertNotNull(vulnerability);
            Assertions.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assertions.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assertions.assertNotNull(vulnerability.getCwes());
            Assertions.assertEquals(1, vulnerability.getCwes().size());
            Assertions.assertEquals(601, vulnerability.getCwes().get(0).intValue());
            Assertions.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", vulnerability.getCvssV3Vector());
            Assertions.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
            Assertions.assertNull(vulnerability.getCreated());
            Assertions.assertNotNull(vulnerability.getPublished());
            Assertions.assertEquals(LocalDateTime.of(2019, 3, 14, 15, 39, 30).toInstant(ZoneOffset.UTC), vulnerability.getPublished().toInstant());
            Assertions.assertNotNull(vulnerability.getUpdated());
            Assertions.assertEquals(LocalDateTime.of(2022, 6, 9, 7, 1, 32, 587000000).toInstant(ZoneOffset.UTC), vulnerability.getUpdated().toInstant());
            Assertions.assertEquals("Skywalker, Solo", vulnerability.getCredits());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:maven/org.springframework.security.oauth/spring-security-oauth"));
        Assertions.assertEquals(4, vulnerableSoftware.size());
        Assertions.assertNull(vulnerableSoftware.get(0).getVersionStartIncluding());
        Assertions.assertEquals("2.0.17", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assertions.assertEquals("2.1.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assertions.assertEquals("2.1.4", vulnerableSoftware.get(1).getVersionEndExcluding());
        Assertions.assertEquals("2.2.0", vulnerableSoftware.get(2).getVersionStartIncluding());
        Assertions.assertEquals("2.2.4", vulnerableSoftware.get(2).getVersionEndExcluding());
        Assertions.assertEquals("2.3.0", vulnerableSoftware.get(3).getVersionStartIncluding());
        Assertions.assertEquals("2.3.5", vulnerableSoftware.get(3).getVersionEndExcluding());

        // The advisory reports both spring-security-oauth and spring-security-oauth2 as affected
        vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:maven/org.springframework.security.oauth/spring-security-oauth2"));
        Assertions.assertEquals(4, vulnerableSoftware.size());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        assertThat(aliases).satisfiesExactly(
                alias -> {
                    assertThat(alias.getCveId()).isEqualTo("CVE-2019-3778");
                    assertThat(alias.getGhsaId()).isEqualTo("GHSA-77rv-6vfw-x4gc");
                }
        );

        // incoming vulnerability when vulnerability with same ID already exists
        prepareJsonObject("src/test/resources/unit/osv.jsons/new-GHSA-77rv-6vfw-x4gc.json");
        advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        task.updateDatasource(advisory);
        vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);
        Assertions.assertNotNull(vulnerability);
        assertVulnerability.accept(vulnerability); // Ensure that the vulnerability was not modified
        Assertions.assertEquals(1, vulnerability.getVulnerableSoftware().size());
        Assertions.assertEquals("3.1.0", vulnerability.getVulnerableSoftware().get(0).getVersionStartIncluding());
        Assertions.assertEquals("3.3.0", vulnerability.getVulnerableSoftware().get(0).getVersionEndExcluding());
    }

    @Test
    void testUpdateDatasourceWithAliasSyncDisabled() throws Exception {
        // Disable alias synchronization
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyName(),
                "false",
                ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyType(),
                null
        );

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        Assertions.assertEquals(8, advisory.getAffectedPackages().size());

        // pass the mapped advisory to OSV task to update the database
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", true);

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        assertThat(aliases).isEmpty();
    }

    @Test
    void testUpdateDatasourceVulnerableVersionRanges() {
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
        final var task = new OsvDownloadTask();
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

        qm.getPersistenceManager().evictAll();
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
    void testParseAdvisoryToVulnerability() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        final var task = new OsvDownloadTask();
        Vulnerability vuln = task.mapAdvisoryToVulnerability(advisory);
        Assertions.assertNotNull(vuln);
        Assertions.assertEquals("Skywalker, Solo", vuln.getCredits());
        Assertions.assertEquals("GITHUB", vuln.getSource());
        Assertions.assertEquals(Severity.CRITICAL, vuln.getSeverity());
        Assertions.assertEquals("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", vuln.getCvssV3Vector());
    }

    @Test
    void testParseAdvisoryToVulnerabilityWithInvalidPurl() throws IOException {
        final var task = new OsvDownloadTask();
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-invalid-purl.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);
        Assertions.assertNotNull(advisory);
        Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-2021-60", true);
        Assertions.assertNotNull(vuln);
        Assertions.assertEquals(Severity.MEDIUM, vuln.getSeverity());
        Assertions.assertEquals(1, vuln.getVulnerableSoftware().size());
    }

    @Test
    void testWithdrawnAdvisory() throws Exception {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-withdrawn.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNull(advisory);
    }

    @Test
    void testSourceOfVulnerability() {
        final var task = new OsvDownloadTask();

        String sourceTestId = "GHSA-77rv-6vfw-x4gc";
        Vulnerability.Source source = task.extractSource(sourceTestId);
        Assertions.assertNotNull(source);
        Assertions.assertEquals(Vulnerability.Source.GITHUB, source);

        sourceTestId = "CVE-2022-tyhg";
        source = task.extractSource(sourceTestId);
        Assertions.assertNotNull(source);
        Assertions.assertEquals(Vulnerability.Source.NVD, source);

        sourceTestId = "anyOther-2022-tyhg";
        source = task.extractSource(sourceTestId);
        Assertions.assertNotNull(source);
        Assertions.assertEquals(Vulnerability.Source.OSV, source);
    }

    @Test
    void testCalculateOSVSeverity() throws IOException {
        final var task = new OsvDownloadTask();
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        Severity severity = task.calculateOSVSeverity(advisory);
        Assertions.assertEquals(Severity.CRITICAL, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-severity-test-ecosystem-cvss.json");
        advisory = parser.parse(jsonObject);
        severity = task.calculateOSVSeverity(advisory);
        Assertions.assertEquals(Severity.CRITICAL, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-severity-test-ecosystem.json");
        advisory = parser.parse(jsonObject);
        severity = task.calculateOSVSeverity(advisory);
        Assertions.assertEquals(Severity.MEDIUM, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-vulnerability-no-range.json");
        advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        severity = task.calculateOSVSeverity(advisory);
        Assertions.assertEquals(Severity.UNASSIGNED, severity);

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-CURL-CVE-2009-0037.json");
        advisory = parser.parse(jsonObject);
        Assertions.assertNotNull(advisory);
        severity = task.calculateOSVSeverity(advisory);
        Assertions.assertEquals(Severity.UNASSIGNED, severity);
    }

    @Test
    void testCommitHashRangesAndVersions() throws IOException {
        final var task = new OsvDownloadTask();

        // insert a vulnerability in database
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-git-commit-hash-ranges.json");
        OsvAdvisory advisory = parser.parse(jsonObject);
        task.updateDatasource(advisory);

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("OSV", "OSV-2021-1820", true);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals(22, vulnerability.getVulnerableSoftware().size());
        Assertions.assertEquals(Severity.MEDIUM, vulnerability.getSeverity());
    }

    @Test
    void testGetEcosystems() {
        stubFor(get(urlPathEqualTo("/ecosystems.txt"))
                .willReturn(aResponse()
                        .proxiedFrom("https://osv-vulnerabilities.storage.googleapis.com")));
        final var task = new OsvDownloadTask();
        List<String> ecosystems = task.getEcosystems();
        Assertions.assertFalse(ecosystems.isEmpty());
        Assertions.assertTrue(ecosystems.contains("Maven"));
    }

    @Test
    void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromEnabledNvdSource() throws IOException {

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
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("NVD", "CVE-2021-34552", false);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
        Assertions.assertEquals(existingVuln.getDescription(), vulnerability.getDescription());

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
    void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromDisabledNvdSource() throws IOException {

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
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("NVD", "CVE-2021-34552", false);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals(Severity.UNASSIGNED, vulnerability.getSeverity());
        Assertions.assertEquals(jsonObject.getString("details"), vulnerability.getDescription());

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
    void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromEnabledGithubSource() throws IOException {

        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json");

        var existingVuln = new Vulnerability();
        existingVuln.setVulnId("GHSA-77rv-6vfw-x4gc");
        existingVuln.setSource(Vulnerability.Source.GITHUB);
        existingVuln.setSeverity(Severity.LOW);
        qm.createVulnerability(existingVuln, false);

        OsvAdvisory advisory = parser.parse(jsonObject);
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", false);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals(Severity.LOW, vulnerability.getSeverity());
    }

    @Test
    void testUpdateDatasourceWithAdvisoryAlreadyMirroredFromDisabledGithubSource() throws IOException {

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
        final var task = new OsvDownloadTask();
        task.updateDatasource(advisory);

        // Reload from database to bypass first level cache
        qm.getPersistenceManager().refreshAll();
        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("GITHUB", "GHSA-77rv-6vfw-x4gc", false);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
    }

    private void prepareJsonObject(String filePath) throws IOException {
        // parse OSV json file to Advisory object
        String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
        jsonObject = new JSONObject(jsonString);
    }
}