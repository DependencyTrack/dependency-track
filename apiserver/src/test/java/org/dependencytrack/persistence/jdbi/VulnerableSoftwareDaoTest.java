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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class VulnerableSoftwareDaoTest extends PersistenceCapableTest {

    private Vulnerability vuln;

    @BeforeEach
    void beforeEach() {
        vuln = new Vulnerability();
        vuln.setVulnId("CVE-2024-0001");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);
    }

    @Test
    void syncAllShouldReuseExistingVulnerableSoftwareByCpe() {
        final VulnerableSoftware existingVs = vulnerableSoftwareOfCpe("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(existingVs);

        sync(List.of(vulnerableSoftwareOfCpe("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*")));

        assertThat(getVulnerableSoftware()).satisfiesExactly(vs -> {
            assertThat(vs.getId()).isEqualTo(existingVs.getId());
            assertThat(vs.getAffectedVersionAttributions())
                    .extracting(AffectedVersionAttribution::getSource)
                    .containsExactly(Vulnerability.Source.NVD);
        });
    }

    @Test
    void syncAllShouldPersistVersionRanges() {
        final VulnerableSoftware vs = vulnerableSoftwareOfCpe("cpe:2.3:a:acme:product:*:*:*:*:*:*:*:*");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");

        sync(List.of(vs));

        assertThat(getVulnerableSoftware()).satisfiesExactly(persistedVs -> {
            assertThat(persistedVs.getVersionStartIncluding()).isEqualTo("1.0.0");
            assertThat(persistedVs.getVersionEndExcluding()).isEqualTo("2.0.0");
        });
    }

    @Test
    void syncAllShouldNotCollapseVulnerableSoftwareWithDifferentPurlQualifiers() {
        sync(List.of(
                vulnerableSoftwareOfPurl(
                        "pkg:deb/debian/sudo@1.9.5?distro=debian-11", "{\"distro\":\"debian-11\"}", null),
                vulnerableSoftwareOfPurl(
                        "pkg:deb/debian/sudo@1.9.5?distro=debian-12", "{\"distro\":\"debian-12\"}", null)));

        assertThat(getVulnerableSoftware())
                .extracting(VulnerableSoftware::getPurlQualifiers)
                .containsExactlyInAnyOrder("{\"distro\":\"debian-11\"}", "{\"distro\":\"debian-12\"}");
    }

    @Test
    void syncAllShouldReuseExistingVulnerableSoftwareByPurlQualifiers() {
        final VulnerableSoftware existingVs = vulnerableSoftwareOfPurl(
                "pkg:deb/debian/sudo@1.9.5?distro=debian-11", "{\"distro\":\"debian-11\"}", null);
        qm.persist(existingVs);
        qm.persist(vulnerableSoftwareOfPurl(
                "pkg:deb/debian/sudo@1.9.5?distro=debian-12", "{\"distro\":\"debian-12\"}", null));

        sync(List.of(vulnerableSoftwareOfPurl(
                "pkg:deb/debian/sudo@1.9.5?distro=debian-11", "{\"distro\":\"debian-11\"}", null)));

        assertThat(getVulnerableSoftware())
                .satisfiesExactly(vs -> assertThat(vs.getId()).isEqualTo(existingVs.getId()));
    }

    @Test
    void syncAllShouldNotCollapseVulnerableSoftwareWithDifferentPurlSubpaths() {
        sync(List.of(
                vulnerableSoftwareOfPurl("pkg:deb/debian/sudo@1.9.5#a", null, "a"),
                vulnerableSoftwareOfPurl("pkg:deb/debian/sudo@1.9.5#b", null, "b")));

        assertThat(getVulnerableSoftware())
                .extracting(VulnerableSoftware::getPurlSubpath)
                .containsExactlyInAnyOrder("a", "b");
    }

    @Test
    void syncAllShouldReuseExistingVulnerableSoftwareByPurlSubpath() {
        final VulnerableSoftware existingVs = vulnerableSoftwareOfPurl("pkg:deb/debian/sudo@1.9.5#a", null, "a");
        qm.persist(existingVs);
        qm.persist(vulnerableSoftwareOfPurl("pkg:deb/debian/sudo@1.9.5#b", null, "b"));

        sync(List.of(vulnerableSoftwareOfPurl("pkg:deb/debian/sudo@1.9.5#a", null, "a")));

        assertThat(getVulnerableSoftware())
                .satisfiesExactly(vs -> assertThat(vs.getId()).isEqualTo(existingVs.getId()));
    }

    private void sync(List<VulnerableSoftware> vsList) {
        final VulnerabilityKey vulnKey = VulnerabilityKey.of(vuln);
        useJdbiTransaction(handle -> new VulnerableSoftwareDao(handle)
                .syncAll(Vulnerability.Source.NVD, Map.of(vulnKey, vuln.getId()), Map.of(vulnKey, vsList)));
    }

    private List<VulnerableSoftware> getVulnerableSoftware() {
        return withJdbiHandle(
                handle -> handle.attach(VulnerabilityDao.class).getVulnerableSoftwareByVulnId(vuln.getId()));
    }

    private static VulnerableSoftware vulnerableSoftwareOfCpe(String cpe23) {
        final var vs = new VulnerableSoftware();
        vs.setCpe23(cpe23);
        return vs;
    }

    private static VulnerableSoftware vulnerableSoftwareOfPurl(String purl, String qualifiers, String subpath) {
        final var vs = new VulnerableSoftware();
        vs.setPurl(purl);
        vs.setPurlType("deb");
        vs.setPurlNamespace("debian");
        vs.setPurlName("sudo");
        vs.setPurlQualifiers(qualifiers);
        vs.setPurlSubpath(subpath);
        vs.setVersion("1.9.5");
        return vs;
    }
}
