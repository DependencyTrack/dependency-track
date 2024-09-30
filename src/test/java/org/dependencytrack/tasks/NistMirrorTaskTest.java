/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_FEEDS_URL;

public class NistMirrorTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @Before
    public void setUp() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_NVD_FEEDS_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_NVD_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_FEEDS_URL.getDescription()
        );
    }

    @Test
    public void test() throws Exception {
        final byte[] gzippedFeedFileBytes = gzipResource("/unit/nvd/feed/nvdcve-1.1-2022.json");

        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withStatus(404)));
        wireMock.stubFor(get(urlPathEqualTo("/json/cve/1.1/nvdcve-1.1-2022.json.gz"))
                .willReturn(aResponse()
                        .withBody(gzippedFeedFileBytes)));
        wireMock.stubFor(get(urlPathEqualTo("/json/cve/1.1/nvdcve-1.1-2022.meta"))
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/feed/nvdcve-1.1-2022.meta"))));

        final Path mirrorDirPath = Files.createTempDirectory(null);
        mirrorDirPath.toFile().deleteOnExit();

        new NistMirrorTask(mirrorDirPath).inform(new NistMirrorEvent());

        assertThat(mirrorDirPath.resolve("nvdcve-1.1-2022.json.gz")).exists();
        assertThat(mirrorDirPath.resolve("nvdcve-1.1-2022.json")).exists();
        assertThat(mirrorDirPath.resolve("nvdcve-1.1-2022.meta")).exists();

        final List<Vulnerability> vulns = qm.getVulnerabilities().getList(Vulnerability.class);
        assertThat(vulns).satisfiesExactlyInAnyOrder(
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-0001");
                    assertThat(vuln.getSource()).isEqualTo("NVD");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            Non-transparent sharing of branch predictor selectors between contexts \
                            in some Intel(R) Processors may allow an authorized user to potentially \
                            enable information disclosure via local access.""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00598.html](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00598.html)
                            * [http://www.openwall.com/lists/oss-security/2022/03/18/2](http://www.openwall.com/lists/oss-security/2022/03/18/2)
                            * [https://www.oracle.com/security-alerts/cpujul2022.html](https://www.oracle.com/security-alerts/cpujul2022.html)
                            * [https://security.netapp.com/advisory/ntap-20220818-0004/](https://security.netapp.com/advisory/ntap-20220818-0004/)
                            * [https://www.kb.cert.org/vuls/id/155143](https://www.kb.cert.org/vuls/id/155143)""");
                    assertThat(vuln.getPublished()).isInSameMinuteAs("2022-03-11T18:15:00Z");
                    assertThat(vuln.getUpdated()).isInSameMinuteAs("2024-04-09T15:15:00Z");
                    assertThat(vuln.getCvssV2BaseScore()).isEqualByComparingTo("2.1");
                    assertThat(vuln.getCvssV2ExploitabilitySubScore()).isEqualByComparingTo("3.9");
                    assertThat(vuln.getCvssV2ImpactSubScore()).isEqualByComparingTo("2.9");
                    assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:L/AC:L/Au:N/C:P/I:N/A:N)");
                    assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("6.5");
                    assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualByComparingTo("2.0");
                    assertThat(vuln.getCvssV3ImpactSubScore()).isEqualByComparingTo("4.0");
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
                },
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-0002");
                    assertThat(vuln.getSource()).isEqualTo("NVD");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            Non-transparent sharing of branch predictor within a context in some \
                            Intel(R) Processors may allow an authorized user to potentially enable \
                            information disclosure via local access.""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00598.html](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00598.html)
                            * [http://www.openwall.com/lists/oss-security/2022/03/18/2](http://www.openwall.com/lists/oss-security/2022/03/18/2)
                            * [https://www.oracle.com/security-alerts/cpujul2022.html](https://www.oracle.com/security-alerts/cpujul2022.html)
                            * [https://security.netapp.com/advisory/ntap-20220818-0004/](https://security.netapp.com/advisory/ntap-20220818-0004/)""");
                    assertThat(vuln.getPublished()).isInSameMinuteAs("2022-03-11T18:15:00Z");
                    assertThat(vuln.getUpdated()).isInSameMinuteAs("2022-08-19T12:28:00Z");
                    assertThat(vuln.getCvssV2BaseScore()).isEqualByComparingTo("2.1");
                    assertThat(vuln.getCvssV2ExploitabilitySubScore()).isEqualByComparingTo("3.9");
                    assertThat(vuln.getCvssV2ImpactSubScore()).isEqualByComparingTo("2.9");
                    assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:L/AC:L/Au:N/C:P/I:N/A:N)");
                    assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("6.5");
                    assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualByComparingTo("2.0");
                    assertThat(vuln.getCvssV3ImpactSubScore()).isEqualByComparingTo("4.0");
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
                },
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-0004");
                    assertThat(vuln.getSource()).isEqualTo("NVD");
                    assertThat(vuln.getDescription()).isEqualTo("""
                            Hardware debug modes and processor INIT setting that allow override of \
                            locks for some Intel(R) Processors in Intel(R) Boot Guard and Intel(R) \
                            TXT may allow an unauthenticated user to potentially enable escalation \
                            of privilege via physical access.""");
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00613.html](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00613.html)""");
                    assertThat(vuln.getPublished()).isInSameMinuteAs("2022-05-12T17:15:00Z");
                    assertThat(vuln.getUpdated()).isInSameMinuteAs("2022-06-10T20:52:00Z");
                    assertThat(vuln.getCvssV2BaseScore()).isEqualByComparingTo("7.2");
                    assertThat(vuln.getCvssV2ExploitabilitySubScore()).isEqualByComparingTo("3.9");
                    assertThat(vuln.getCvssV2ImpactSubScore()).isEqualByComparingTo("10.0");
                    assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:L/AC:L/Au:N/C:C/I:C/A:C)");
                    assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("6.8");
                    assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualByComparingTo("0.9");
                    assertThat(vuln.getCvssV3ImpactSubScore()).isEqualByComparingTo("5.9");
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
                    assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
                }
        );
    }

    @Test
    public void testWithDuplicateCpes() throws Exception {
        final byte[] gzippedFeedFileBytes = gzipResource("/unit/nvd/feed/nvdcve-1.1-2021_duplicate-cpes.json");

        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withStatus(404)));
        wireMock.stubFor(get(urlPathEqualTo("/json/cve/1.1/nvdcve-1.1-2021.json.gz"))
                .willReturn(aResponse()
                        .withBody(gzippedFeedFileBytes)));

        final Path mirrorDirPath = Files.createTempDirectory(null);
        mirrorDirPath.toFile().deleteOnExit();

        new NistMirrorTask(mirrorDirPath).inform(new NistMirrorEvent());

        final List<Vulnerability> vulns = qm.getVulnerabilities().getList(Vulnerability.class);
        assertThat(vulns).hasSize(1);

        final Vulnerability vuln = vulns.get(0);
        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/o:intel:ethernet_controller_e810_firmware:::~~~linux~~");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:o:intel:ethernet_controller_e810_firmware:*:*:*:*:*:linux:*:*");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/o:fedoraproject:fedora:33");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*");
                },
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/o:fedoraproject:fedora:34");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*");
                },
                vs -> {
                    // This CPE appears twice in the feed file. We must only record it once.
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/o:fedoraproject:fedora:35");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*");
                }
        );
    }

    private byte[] gzipResource(final String resourcePath) throws Exception {
        final var byteArrayOutputStream = new ByteArrayOutputStream();
        try (final var gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
            gzipOutputStream.write(resourceToByteArray(resourcePath));
        }

        return byteArrayOutputStream.toByteArray();
    }

}