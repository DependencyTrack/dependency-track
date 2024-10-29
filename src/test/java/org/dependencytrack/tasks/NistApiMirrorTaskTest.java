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

import alpine.model.ConfigProperty;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.NistApiMirrorEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_URL;

public class NistApiMirrorTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @Before
    public void setUp() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_URL.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_NVD_API_URL.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_API_URL.getDescription()
        );
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName(),
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getDefaultPropertyValue(),
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getDescription()
        );
    }

    @Test
    public void testInformWithNewVulnerability() throws Exception {
        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/api/jsons/cve-2022-1954.json"))));

        new NistApiMirrorTask().inform(new NistApiMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.NVD, "CVE-2022-1954", true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getFriendlyVulnId()).isNull();
        assertThat(vuln.getTitle()).isNull();
        assertThat(vuln.getSubTitle()).isNull();
        assertThat(vuln.getDescription()).isEqualTo("""
                A Regular Expression Denial of Service vulnerability in GitLab CE/EE affecting all versions \
                from 1.0.2 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker \
                to make a GitLab instance inaccessible via specially crafted web server response headers""");
        assertThat(vuln.getDetail()).isNull();
        assertThat(vuln.getRecommendation()).isNull();
        assertThat(vuln.getReferences()).isEqualTo("""
                * [https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1954.json](https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1954.json)
                * [https://gitlab.com/gitlab-org/gitlab/-/issues/358160](https://gitlab.com/gitlab-org/gitlab/-/issues/358160)
                * [https://hackerone.com/reports/1531958](https://hackerone.com/reports/1531958)""");
        assertThat(vuln.getCredits()).isNull();
        assertThat(vuln.getCreated()).isNull();
        assertThat(vuln.getPublished()).isEqualTo("2022-07-01T18:15:08.570Z");
        assertThat(vuln.getUpdated()).isEqualTo("2023-08-08T14:22:24.967Z");
        assertThat(vuln.getCwes()).containsOnly(1333);
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:L/Au:N/C:N/I:N/A:P)");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
        assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(vuln.getVulnerableVersions()).isNull();
        assertThat(vuln.getPatchedVersions()).isNull();
        assertThat(vuln.getEpssScore()).isNull();
        assertThat(vuln.getEpssPercentile()).isNull();
        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                vs -> {
                    assertThat(vs.getCpe22()).isEqualTo("cpe:/a:gitlab:gitlab:::~~community~~~");
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("community");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("1.0.2");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("14.10.5");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("enterprise");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("1.0.2");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("14.10.5");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("community");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("15.0.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("15.0.4");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("*");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("enterprise");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isEqualTo("15.0.0");
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("15.0.4");
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:15.1.0:*:*:*:community:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("15.1.0");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("community");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:15.1.0:*:*:*:enterprise:*:*:*");
                    assertThat(vs.getPart()).isEqualTo("a");
                    assertThat(vs.getVendor()).isEqualTo("gitlab");
                    assertThat(vs.getProduct()).isEqualTo("gitlab");
                    assertThat(vs.getVersion()).isEqualTo("15.1.0");
                    assertThat(vs.getUpdate()).isEqualTo("*");
                    assertThat(vs.getEdition()).isEqualTo("*");
                    assertThat(vs.getLanguage()).isEqualTo("*");
                    assertThat(vs.getSwEdition()).isEqualTo("enterprise");
                    assertThat(vs.getTargetSw()).isEqualTo("*");
                    assertThat(vs.getTargetHw()).isEqualTo("*");
                    assertThat(vs.getOther()).isEqualTo("*");
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isNull();
                    assertThat(vs.isVulnerable()).isTrue();
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isTrue();
                }
        );

        // Property is in L1 cache because it was created in the test's setUp method.
        // Evict L1 cache to reach L2 cache / datastore instead.
        qm.getPersistenceManager().evictAll();
        final ConfigProperty lastModifiedProperty = qm.getConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName()
        );
        assertThat(lastModifiedProperty).isNotNull();
        assertThat(lastModifiedProperty.getPropertyValue()).isEqualTo("1691504544");
    }

    @Test
    public void testInformWithUpdatedVulnerability() throws Exception {
        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2022-1954");
        vuln.setSource(Source.NVD);
        vuln.setTitle("oldTitle");
        vuln.setDescription("oldDescription");
        vuln.setCwes(List.of(333, 666));
        vuln.setCreated(new Date());
        vuln.setPublished(new Date());
        vuln.setUpdated(new Date());
        vuln.setEpssScore(BigDecimal.valueOf(0.3));
        vuln.setEpssPercentile(BigDecimal.valueOf(0.6));
        qm.persist(vuln);

        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/api/jsons/cve-2022-1954.json"))));

        new NistApiMirrorTask().inform(new NistApiMirrorEvent());

        qm.getPersistenceManager().refresh(vuln);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getTitle()).isNull(); // Overwritten with null
        assertThat(vuln.getDescription()).isEqualTo("""
                A Regular Expression Denial of Service vulnerability in GitLab CE/EE affecting all versions \
                from 1.0.2 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker \
                to make a GitLab instance inaccessible via specially crafted web server response headers""");
        assertThat(vuln.getCwes()).containsOnly(1333);
        assertThat(vuln.getCreated()).isNull(); // Overwritten with null
        assertThat(vuln.getPublished()).isEqualTo("2022-07-01T18:15:08.570Z");
        assertThat(vuln.getUpdated()).isEqualTo("2023-08-08T14:22:24.967Z");
        assertThat(vuln.getEpssScore()).isEqualByComparingTo("0.3"); // Not overwritten with null
        assertThat(vuln.getEpssPercentile()).isEqualByComparingTo("0.6"); // Not overwritten with null
    }

    @Test
    public void testInformWithUpdatedVulnerableSoftware() throws Exception {
        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2022-1954");
        vuln.setSource(Source.NVD);
        qm.persist(vuln);

        final var oldAttributionDate = Date.from(Instant.EPOCH);

        // Create a VulnerableSoftware that is attributed to the NVD, but no longer reported.
        // It must be disassociated from the vulnerability, and the attribution removed.
        final var oldVsReportedByNvd = new VulnerableSoftware();
        oldVsReportedByNvd.setCpe23("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*");
        qm.persist(oldVsReportedByNvd);
        final var oldVsReportedByNvdAttribution = new AffectedVersionAttribution();
        oldVsReportedByNvdAttribution.setSource(Source.NVD);
        oldVsReportedByNvdAttribution.setVulnerability(vuln);
        oldVsReportedByNvdAttribution.setVulnerableSoftware(oldVsReportedByNvd);
        oldVsReportedByNvdAttribution.setFirstSeen(oldAttributionDate);
        oldVsReportedByNvdAttribution.setLastSeen(oldAttributionDate);
        qm.persist(oldVsReportedByNvdAttribution);

        // Create a VulnerableSoftware that is attributed to the NVD, and is still reported.
        // It and its attribution must be retained, but the attribution's lastSeen timestamp must be updated.
        final var vsReportedByNvd = new VulnerableSoftware();
        vsReportedByNvd.setCpe22("cpe:/a:gitlab:gitlab:15.1.0::~~enterprise~~~");
        vsReportedByNvd.setCpe23("cpe:2.3:a:gitlab:gitlab:15.1.0:*:*:*:enterprise:*:*:*");
        vsReportedByNvd.setPart("a");
        vsReportedByNvd.setVendor("gitlab");
        vsReportedByNvd.setProduct("gitlab");
        vsReportedByNvd.setVersion("15.1.0");
        vsReportedByNvd.setUpdate("*");
        vsReportedByNvd.setEdition("*");
        vsReportedByNvd.setLanguage("*");
        vsReportedByNvd.setSwEdition("enterprise");
        vsReportedByNvd.setTargetSw("*");
        vsReportedByNvd.setTargetHw("*");
        vsReportedByNvd.setOther("*");
        vsReportedByNvd.setVulnerable(true);
        qm.persist(vsReportedByNvd);
        final var vsReportedByNvdAttribution = new AffectedVersionAttribution();
        vsReportedByNvdAttribution.setSource(Source.NVD);
        vsReportedByNvdAttribution.setVulnerability(vuln);
        vsReportedByNvdAttribution.setVulnerableSoftware(vsReportedByNvd);
        vsReportedByNvdAttribution.setFirstSeen(oldAttributionDate);
        vsReportedByNvdAttribution.setLastSeen(oldAttributionDate);
        qm.persist(vsReportedByNvdAttribution);

        // Create a VulnerableSoftware that is attributed to OSV.
        // It and its attribution must be retained.
        final var vsReportedByOsv = new VulnerableSoftware();
        vsReportedByOsv.setPurl("pkg:generic/linux/kernel@1.2.3");
        qm.persist(vsReportedByOsv);
        final var oldVsReportedByOsvAttribution = new AffectedVersionAttribution();
        oldVsReportedByOsvAttribution.setSource(Source.OSV);
        oldVsReportedByOsvAttribution.setVulnerability(vuln);
        oldVsReportedByOsvAttribution.setVulnerableSoftware(vsReportedByOsv);
        oldVsReportedByOsvAttribution.setFirstSeen(oldAttributionDate);
        oldVsReportedByOsvAttribution.setLastSeen(oldAttributionDate);
        qm.persist(oldVsReportedByOsvAttribution);

        vuln.setVulnerableSoftware(List.of(oldVsReportedByNvd, vsReportedByNvd, vsReportedByOsv));
        qm.persist(vuln);

        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/api/jsons/cve-2022-1954.json"))));

        new NistApiMirrorTask().inform(new NistApiMirrorEvent());

        // Clear L1 cache to force objects that were modified by NistApiMirrorTask
        // to be reloaded when running assertions on them.
        qm.getPersistenceManager().evictAll();

        assertThat(vuln.getVulnerableSoftware()).satisfiesExactlyInAnyOrder(
                vs -> {
                    assertThat(vs.getPurl()).isEqualTo("pkg:generic/linux/kernel@1.2.3");
                    assertThat(qm.hasAffectedVersionAttribution(vuln, vs, Source.NVD)).isFalse();
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.OSV);
                    assertThat(attribution.getFirstSeen()).isEqualTo(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isEqualTo(oldAttributionDate); // Not modified because reported by another source
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:15.1.0:*:*:*:enterprise:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isEqualTo(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate); // Modified because still reported
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isAfter(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate);
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isAfter(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate);
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isAfter(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate);
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isAfter(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate);
                },
                vs -> {
                    assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:gitlab:gitlab:15.1.0:*:*:*:community:*:*:*");
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vuln, vs, Source.NVD);
                    assertThat(attribution.getFirstSeen()).isAfter(oldAttributionDate);
                    assertThat(attribution.getLastSeen()).isAfter(oldAttributionDate);
                }
        );
    }

    @Test
    public void testInformWithIgnoringAmbiguousRunningOnCpeMatches() throws Exception {
        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/api/jsons/cve-2015-0312.json"))));

        new NistApiMirrorTask().inform(new NistApiMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.NVD, "CVE-2015-0312");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).extracting(VulnerableSoftware::getCpe23).containsExactlyInAnyOrder(
                // Ignoring "running on/with" CPE matches:
                //   cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*
                "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
                // Ignoring "running on/with" CPE matches:
                //   cpe:2.3:a:microsoft:internet_explorer:10:*:*:*:*:*:*:*
                //   cpe:2.3:a:microsoft:internet_explorer:11:-:*:*:*:*:*:*
                //   cpe:2.3:o:microsoft:windows_8:-:*:*:*:*:*:*:*
                //   cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*
                "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
                // Ignoring "running on/with" CPE matches:
                //   cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*
                //   cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*
                //   cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*
                "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:chrome:*:*",
                // Ignoring "running on/with" CPE matches:
                //   cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*
                //   cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*
                "cpe:2.3:a:adobe:flash_player:*:*:*:*:extended_support:*:*:*",
                // Ignoring "running on/with" CPE matches:
                //   cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*
                //    cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*
                "cpe:2.3:a:adobe:flash_player_desktop_runtime:*:*:*:*:*:*:*:*"
        );
    }

    @Test
public void testInformWithIgnoringAmbiguousRunningOnCpeMatchesAlt() throws Exception {
        wireMock.stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withBody(resourceToByteArray("/unit/nvd/api/jsons/cve-2024-23113.json"))));

        new NistApiMirrorTask().inform(new NistApiMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.NVD, "CVE-2024-23113");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).extracting(VulnerableSoftware::getCpe23).containsExactlyInAnyOrder(
                "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortipam:1.2.0:*:*:*:*:*:*:*"
        );
    }
}