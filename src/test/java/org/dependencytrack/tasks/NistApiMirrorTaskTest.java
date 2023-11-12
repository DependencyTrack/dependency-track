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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

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

        new NistApiMirrorTask().inform(new NistMirrorEvent());

        assertThat(qm.getCount(Vulnerability.class)).isEqualTo(1);

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
    }

}