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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class VulnerableSoftwareQueryManagerTest extends PersistenceCapableTest {

    private Vulnerability vulnerability;

    @BeforeEach
    public void setUp() {
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-0001");
        vulnerability.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnerability);
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithNewVulnerableSoftware() {
        // Create a new VulnerableSoftware
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // Synchronize
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        // Verify the VulnerableSoftware was created and linked
        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);
        assertThat(persistedVuln.getVulnerableSoftware().get(0).getCpe23()).isEqualTo("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // Verify attribution was created
        final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(
                persistedVuln,
                persistedVuln.getVulnerableSoftware().get(0),
                Vulnerability.Source.NVD
        );
        assertThat(attribution).isNotNull();
        assertThat(attribution.getSource()).isEqualTo(Vulnerability.Source.NVD);
    }

    @Test
    public void testSynchronizeVulnerableSoftwareDoesNotCreateDuplicateAttribution() {
        // This test verifies the bug fix: duplicate attributions should not be created
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // First synchronization
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        // Wait a bit to ensure different timestamps
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Second synchronization with the same data - should NOT create duplicate attribution
        // Create a new transient object for the second call
        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        assertThatNoException().isThrownBy(() -> {
            qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs2), Vulnerability.Source.NVD);
        });

        // Verify only one attribution exists
        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);

        final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(
                persistedVuln,
                persistedVuln.getVulnerableSoftware()
        );
        assertThat(attributions).hasSize(1);
        assertThat(attributions.get(0).getSource()).isEqualTo(Vulnerability.Source.NVD);
    }

    @Test
    public void testSynchronizeVulnerableSoftwareUpdatesLastSeen() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // First synchronization
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln1 = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        final AffectedVersionAttribution attribution1 = qm.getAffectedVersionAttribution(
                persistedVuln1,
                persistedVuln1.getVulnerableSoftware().get(0),
                Vulnerability.Source.NVD
        );
        final Date firstLastSeen = attribution1.getLastSeen();

        // Wait to ensure different timestamp
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Second synchronization - create a new transient object
        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs2), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln2 = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        final AffectedVersionAttribution attribution2 = qm.getAffectedVersionAttribution(
                persistedVuln2,
                persistedVuln2.getVulnerableSoftware().get(0),
                Vulnerability.Source.NVD
        );

        // Verify lastSeen was updated
        assertThat(attribution2.getLastSeen()).isAfter(firstLastSeen);
        // Verify firstSeen was not changed
        assertThat(attribution2.getFirstSeen()).isEqualTo(attribution1.getFirstSeen());
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithExistingVulnerableSoftware() {
        // Create and persist a VulnerableSoftware first
        final VulnerableSoftware existingVs = new VulnerableSoftware();
        existingVs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(existingVs);

        // Create a new VulnerableSoftware with the same CPE (but transient)
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // Synchronize - should reuse existing VulnerableSoftware
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);
        // Verify it's the same instance (same ID)
        assertThat(persistedVuln.getVulnerableSoftware().get(0).getId()).isEqualTo(existingVs.getId());
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithMultipleSources() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        // Synchronize with NVD source
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        // Synchronize with OSV source - should create separate attribution
        // Create a new transient object for the second call
        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs2), Vulnerability.Source.OSV);

        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);

        final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(
                persistedVuln,
                persistedVuln.getVulnerableSoftware()
        );
        assertThat(attributions).hasSize(2);
        assertThat(attributions).extracting(AffectedVersionAttribution::getSource)
                .containsExactlyInAnyOrder(Vulnerability.Source.NVD, Vulnerability.Source.OSV);
    }

    @Test
    public void testSynchronizeVulnerableSoftwareRemovesUnreportedVulnerableSoftware() {
        // Create initial VulnerableSoftware
        final VulnerableSoftware vs1 = new VulnerableSoftware();
        vs1.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs1), Vulnerability.Source.NVD);

        // Verify it's linked
        Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);

        // Synchronize with different VulnerableSoftware
        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:2.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs2), Vulnerability.Source.NVD);

        // Verify old one is removed and new one is added
        persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);
        assertThat(persistedVuln.getVulnerableSoftware().get(0).getCpe23()).isEqualTo("cpe:2.3:a:acme:product:2.0.0:*:*:*:*:*:*:*");
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithPurl() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPurl("pkg:maven/org.acme/product@1.0.0");
        vs.setPurlType("maven");
        vs.setPurlNamespace("org.acme");
        vs.setPurlName("product");
        vs.setVersion("1.0.0");

        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.OSV);

        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);
        assertThat(persistedVuln.getVulnerableSoftware().get(0).getPurl()).isEqualTo("pkg:maven/org.acme/product@1.0.0");
    }

    @Test
    public void testGetVulnerableSoftwareByCpe23() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        vs.setVersionEndExcluding("1.1.0");
        qm.persist(vs);

        final VulnerableSoftware found = qm.getVulnerableSoftwareByCpe23(
                "cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*",
                "1.1.0",
                null,
                null,
                null
        );

        assertThat(found).isNotNull();
        assertThat(found.getCpe23()).isEqualTo("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        assertThat(found.getVersionEndExcluding()).isEqualTo("1.1.0");
    }

    @Test
    public void testGetVulnerableSoftwareByCpe23WithNullVersionRanges() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(vs);

        final VulnerableSoftware found = qm.getVulnerableSoftwareByCpe23(
                "cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*",
                null,
                null,
                null,
                null
        );

        assertThat(found).isNotNull();
        assertThat(found.getCpe23()).isEqualTo("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    public void testGetVulnerableSoftwareByPurl() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPurl("pkg:maven/org.acme/product@1.0.0");
        vs.setPurlType("maven");
        vs.setPurlNamespace("org.acme");
        vs.setPurlName("product");
        vs.setVersion("1.0.0");
        vs.setVersionEndExcluding("1.1.0");
        qm.persist(vs);

        final VulnerableSoftware found = qm.getVulnerableSoftwareByPurl(
                "maven",
                "org.acme",
                "product",
                "1.0.0",
                "1.1.0",
                null,
                null,
                null
        );

        assertThat(found).isNotNull();
        assertThat(found.getPurl()).isEqualTo("pkg:maven/org.acme/product@1.0.0");
        assertThat(found.getPurlType()).isEqualTo("maven");
        assertThat(found.getPurlNamespace()).isEqualTo("org.acme");
        assertThat(found.getPurlName()).isEqualTo("product");
    }

    @Test
    public void testGetVulnerableSoftwareByPurlWithNullNamespace() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPurl("pkg:npm/product@1.0.0");
        vs.setPurlType("npm");
        vs.setPurlNamespace(null);
        vs.setPurlName("product");
        vs.setVersion("1.0.0");
        qm.persist(vs);

        final VulnerableSoftware found = qm.getVulnerableSoftwareByPurl(
                "npm",
                null,
                "product",
                "1.0.0",
                null,
                null,
                null,
                null
        );

        assertThat(found).isNotNull();
        assertThat(found.getPurlType()).isEqualTo("npm");
        assertThat(found.getPurlNamespace()).isNull();
        assertThat(found.getPurlName()).isEqualTo("product");
    }

    @Test
    public void shouldDistinguishVulnerableSoftwareByPurlQualifiers() {
        final VulnerableSoftware vsBullseye = new VulnerableSoftware();
        vsBullseye.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-11");
        vsBullseye.setPurlType("deb");
        vsBullseye.setPurlNamespace("debian");
        vsBullseye.setPurlName("sudo");
        vsBullseye.setPurlQualifiers("{\"distro\":\"debian-11\"}");
        vsBullseye.setVersion("1.9.5");
        qm.persist(vsBullseye);

        final VulnerableSoftware vsBookworm = new VulnerableSoftware();
        vsBookworm.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-12");
        vsBookworm.setPurlType("deb");
        vsBookworm.setPurlNamespace("debian");
        vsBookworm.setPurlName("sudo");
        vsBookworm.setPurlQualifiers("{\"distro\":\"debian-12\"}");
        vsBookworm.setVersion("1.9.5");
        qm.persist(vsBookworm);

        final VulnerableSoftware vsNoQualifiers = new VulnerableSoftware();
        vsNoQualifiers.setPurl("pkg:deb/debian/sudo@1.9.5");
        vsNoQualifiers.setPurlType("deb");
        vsNoQualifiers.setPurlNamespace("debian");
        vsNoQualifiers.setPurlName("sudo");
        vsNoQualifiers.setVersion("1.9.5");
        qm.persist(vsNoQualifiers);

        final VulnerableSoftware foundBullseye = qm.getVulnerableSoftwareByPurl(
                "deb", "debian", "sudo", "{\"distro\":\"debian-11\"}", null,
                "1.9.5", null, null, null, null);
        assertThat(foundBullseye).isNotNull();
        assertThat(foundBullseye.getId()).isEqualTo(vsBullseye.getId());

        final VulnerableSoftware foundBookworm = qm.getVulnerableSoftwareByPurl(
                "deb", "debian", "sudo", "{\"distro\":\"debian-12\"}", null,
                "1.9.5", null, null, null, null);
        assertThat(foundBookworm).isNotNull();
        assertThat(foundBookworm.getId()).isEqualTo(vsBookworm.getId());

        final VulnerableSoftware foundNone = qm.getVulnerableSoftwareByPurl(
                "deb", "debian", "sudo", null, null,
                "1.9.5", null, null, null, null);
        assertThat(foundNone).isNotNull();
        assertThat(foundNone.getId()).isEqualTo(vsNoQualifiers.getId());

        final VulnerableSoftware foundUnknown = qm.getVulnerableSoftwareByPurl(
                "deb", "debian", "sudo", "{\"distro\":\"debian-13\"}", null,
                "1.9.5", null, null, null, null);
        assertThat(foundUnknown).isNull();
    }

    @Test
    public void shouldSynchronizeVulnerableSoftwareByPurlQualifiersWithoutCollapsingRows() {
        final VulnerableSoftware vsBullseye = new VulnerableSoftware();
        vsBullseye.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-11");
        vsBullseye.setPurlType("deb");
        vsBullseye.setPurlNamespace("debian");
        vsBullseye.setPurlName("sudo");
        vsBullseye.setPurlQualifiers("{\"distro\":\"debian-11\"}");
        vsBullseye.setVersion("1.9.5");

        final VulnerableSoftware vsBookworm = new VulnerableSoftware();
        vsBookworm.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-12");
        vsBookworm.setPurlType("deb");
        vsBookworm.setPurlNamespace("debian");
        vsBookworm.setPurlName("sudo");
        vsBookworm.setPurlQualifiers("{\"distro\":\"debian-12\"}");
        vsBookworm.setVersion("1.9.5");

        qm.synchronizeVulnerableSoftware(
                vulnerability, List.of(vsBullseye, vsBookworm), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln =
                qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware())
                .extracting(VulnerableSoftware::getPurlQualifiers)
                .containsExactlyInAnyOrder(
                        "{\"distro\":\"debian-11\"}",
                        "{\"distro\":\"debian-12\"}");
    }

    @Test
    public void shouldReuseVulnerableSoftwareByPurlQualifiersOnSubsequentSync() {
        final VulnerableSoftware preExisting = new VulnerableSoftware();
        preExisting.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-11");
        preExisting.setPurlType("deb");
        preExisting.setPurlNamespace("debian");
        preExisting.setPurlName("sudo");
        preExisting.setPurlQualifiers("{\"distro\":\"debian-11\"}");
        preExisting.setVersion("1.9.5");
        qm.persist(preExisting);

        final VulnerableSoftware otherDistro = new VulnerableSoftware();
        otherDistro.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-12");
        otherDistro.setPurlType("deb");
        otherDistro.setPurlNamespace("debian");
        otherDistro.setPurlName("sudo");
        otherDistro.setPurlQualifiers("{\"distro\":\"debian-12\"}");
        otherDistro.setVersion("1.9.5");
        qm.persist(otherDistro);

        final VulnerableSoftware reported = new VulnerableSoftware();
        reported.setPurl("pkg:deb/debian/sudo@1.9.5?distro=debian-11");
        reported.setPurlType("deb");
        reported.setPurlNamespace("debian");
        reported.setPurlName("sudo");
        reported.setPurlQualifiers("{\"distro\":\"debian-11\"}");
        reported.setVersion("1.9.5");

        qm.synchronizeVulnerableSoftware(
                vulnerability, List.of(reported), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln =
                qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).satisfiesExactly(vs -> {
                    assertThat(vs.getId()).isEqualTo(preExisting.getId());
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(
                            persistedVuln, vs, Vulnerability.Source.NVD);
                    assertThat(attribution).isNotNull();
                });
    }

    @Test
    public void shouldDistinguishVulnerableSoftwareByPurlSubpath() {
        final VulnerableSoftware vsSubA = new VulnerableSoftware();
        vsSubA.setPurl("pkg:generic/acme/product@1.0.0#a");
        vsSubA.setPurlType("generic");
        vsSubA.setPurlNamespace("acme");
        vsSubA.setPurlName("product");
        vsSubA.setPurlSubpath("a");
        vsSubA.setVersion("1.0.0");
        qm.persist(vsSubA);

        final VulnerableSoftware vsSubB = new VulnerableSoftware();
        vsSubB.setPurl("pkg:generic/acme/product@1.0.0#b");
        vsSubB.setPurlType("generic");
        vsSubB.setPurlNamespace("acme");
        vsSubB.setPurlName("product");
        vsSubB.setPurlSubpath("b");
        vsSubB.setVersion("1.0.0");
        qm.persist(vsSubB);

        final VulnerableSoftware vsNoSubpath = new VulnerableSoftware();
        vsNoSubpath.setPurl("pkg:generic/acme/product@1.0.0");
        vsNoSubpath.setPurlType("generic");
        vsNoSubpath.setPurlNamespace("acme");
        vsNoSubpath.setPurlName("product");
        vsNoSubpath.setVersion("1.0.0");
        qm.persist(vsNoSubpath);

        final VulnerableSoftware foundA = qm.getVulnerableSoftwareByPurl(
                "generic", "acme", "product", null, "a",
                "1.0.0", null, null, null, null);
        assertThat(foundA).isNotNull();
        assertThat(foundA.getId()).isEqualTo(vsSubA.getId());

        final VulnerableSoftware foundB = qm.getVulnerableSoftwareByPurl(
                "generic", "acme", "product", null, "b",
                "1.0.0", null, null, null, null);
        assertThat(foundB).isNotNull();
        assertThat(foundB.getId()).isEqualTo(vsSubB.getId());

        final VulnerableSoftware foundNone = qm.getVulnerableSoftwareByPurl(
                "generic", "acme", "product", null, null,
                "1.0.0", null, null, null, null);
        assertThat(foundNone).isNotNull();
        assertThat(foundNone.getId()).isEqualTo(vsNoSubpath.getId());

        final VulnerableSoftware foundUnknown = qm.getVulnerableSoftwareByPurl(
                "generic", "acme", "product", null, "c",
                "1.0.0", null, null, null, null);
        assertThat(foundUnknown).isNull();
    }

    @Test
    public void shouldSynchronizeVulnerableSoftwareByPurlSubpathWithoutCollapsingRows() {
        final VulnerableSoftware vsSubA = new VulnerableSoftware();
        vsSubA.setPurl("pkg:generic/acme/product@1.0.0#a");
        vsSubA.setPurlType("generic");
        vsSubA.setPurlNamespace("acme");
        vsSubA.setPurlName("product");
        vsSubA.setPurlSubpath("a");
        vsSubA.setVersion("1.0.0");

        final VulnerableSoftware vsSubB = new VulnerableSoftware();
        vsSubB.setPurl("pkg:generic/acme/product@1.0.0#b");
        vsSubB.setPurlType("generic");
        vsSubB.setPurlNamespace("acme");
        vsSubB.setPurlName("product");
        vsSubB.setPurlSubpath("b");
        vsSubB.setVersion("1.0.0");

        qm.synchronizeVulnerableSoftware(
                vulnerability, List.of(vsSubA, vsSubB), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln =
                qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware())
                .extracting(VulnerableSoftware::getPurlSubpath)
                .containsExactlyInAnyOrder("a", "b");
    }

    @Test
    public void shouldReuseVulnerableSoftwareByPurlSubpathOnSubsequentSync() {
        final VulnerableSoftware preExisting = new VulnerableSoftware();
        preExisting.setPurl("pkg:generic/acme/product@1.0.0#a");
        preExisting.setPurlType("generic");
        preExisting.setPurlNamespace("acme");
        preExisting.setPurlName("product");
        preExisting.setPurlSubpath("a");
        preExisting.setVersion("1.0.0");
        qm.persist(preExisting);

        final VulnerableSoftware otherSubpath = new VulnerableSoftware();
        otherSubpath.setPurl("pkg:generic/acme/product@1.0.0#b");
        otherSubpath.setPurlType("generic");
        otherSubpath.setPurlNamespace("acme");
        otherSubpath.setPurlName("product");
        otherSubpath.setPurlSubpath("b");
        otherSubpath.setVersion("1.0.0");
        qm.persist(otherSubpath);

        final VulnerableSoftware reported = new VulnerableSoftware();
        reported.setPurl("pkg:generic/acme/product@1.0.0#a");
        reported.setPurlType("generic");
        reported.setPurlNamespace("acme");
        reported.setPurlName("product");
        reported.setPurlSubpath("a");
        reported.setVersion("1.0.0");

        qm.synchronizeVulnerableSoftware(
                vulnerability, List.of(reported), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln =
                qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).satisfiesExactly(vs -> {
                    assertThat(vs.getId()).isEqualTo(preExisting.getId());
                    final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(
                            persistedVuln, vs, Vulnerability.Source.NVD);
                    assertThat(attribution).isNotNull();
                });
    }

    @Test
    public void testHasAffectedVersionAttribution() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(vs);

        // Initially, no attribution exists
        assertThat(qm.hasAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.NVD)).isFalse();

        // Create attribution using a new transient object
        final VulnerableSoftware vsTransient = new VulnerableSoftware();
        vsTransient.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vsTransient), Vulnerability.Source.NVD);

        // Now attribution should exist
        assertThat(qm.hasAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.NVD)).isTrue();
    }

    @Test
    public void testHasAffectedVersionAttributionWithDifferentSource() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(vs);

        // Create attribution with NVD source using a new transient object
        final VulnerableSoftware vsTransient = new VulnerableSoftware();
        vsTransient.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vsTransient), Vulnerability.Source.NVD);

        // Check for NVD - should exist
        assertThat(qm.hasAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.NVD)).isTrue();

        // Check for OSV - should not exist
        assertThat(qm.hasAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.OSV)).isFalse();
    }

    @Test
    public void testGetAffectedVersionAttribution() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.persist(vs);

        // Initially, no attribution exists
        assertThat(qm.getAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.NVD)).isNull();

        // Create attribution using a new transient object
        final VulnerableSoftware vsTransient = new VulnerableSoftware();
        vsTransient.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vsTransient), Vulnerability.Source.NVD);

        // Retrieve attribution using the persisted VS
        final AffectedVersionAttribution attribution = qm.getAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.NVD);
        assertThat(attribution).isNotNull();
        assertThat(attribution.getSource()).isEqualTo(Vulnerability.Source.NVD);
        assertThat(attribution.getVulnerability()).isEqualTo(vulnerability);
        assertThat(attribution.getVulnerableSoftware().getId()).isEqualTo(vs.getId());
        assertThat(attribution.getFirstSeen()).isNotNull();
        assertThat(attribution.getLastSeen()).isNotNull();
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithEmptyList() {
        // Initially add some VulnerableSoftware
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);

        // Synchronize with empty list - should remove all VulnerableSoftware
        qm.synchronizeVulnerableSoftware(vulnerability, new ArrayList<>(), Vulnerability.Source.NVD);

        persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    public void testSynchronizeVulnerableSoftwarePreservesAttributionsFromOtherSources() {
        // First, synchronize with OSV source
        final VulnerableSoftware vs1 = new VulnerableSoftware();
        vs1.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs1), Vulnerability.Source.OSV);

        // Then synchronize with NVD source using a new transient object
        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs2), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(
                persistedVuln,
                persistedVuln.getVulnerableSoftware()
        );

        // Both attributions should exist
        assertThat(attributions).hasSize(2);
        assertThat(attributions).extracting(AffectedVersionAttribution::getSource)
                .containsExactlyInAnyOrder(Vulnerability.Source.OSV, Vulnerability.Source.NVD);
    }

    @Test
    public void testSynchronizeVulnerableSoftwareWithVersionRanges() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:acme:product:*:*:*:*:*:*:*:*");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");

        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs), Vulnerability.Source.NVD);

        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(1);
        final VulnerableSoftware persistedVs = persistedVuln.getVulnerableSoftware().get(0);
        assertThat(persistedVs.getVersionStartIncluding()).isEqualTo("1.0.0");
        assertThat(persistedVs.getVersionEndExcluding()).isEqualTo("2.0.0");
    }

    @Test
    public void testMultipleSynchronizationsDoNotCreateDuplicates() {
        // This is a comprehensive test to ensure the bug is fixed
        final VulnerableSoftware vs1 = new VulnerableSoftware();
        vs1.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

        final VulnerableSoftware vs2 = new VulnerableSoftware();
        vs2.setCpe23("cpe:2.3:a:acme:product:2.0.0:*:*:*:*:*:*:*");

        // First synchronization
        qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs1, vs2), Vulnerability.Source.NVD);

        // Multiple subsequent synchronizations with same data
        for (int i = 0; i < 5; i++) {
            final VulnerableSoftware vs1Copy = new VulnerableSoftware();
            vs1Copy.setCpe23("cpe:2.3:a:acme:product:1.0.0:*:*:*:*:*:*:*");

            final VulnerableSoftware vs2Copy = new VulnerableSoftware();
            vs2Copy.setCpe23("cpe:2.3:a:acme:product:2.0.0:*:*:*:*:*:*:*");

            assertThatNoException().isThrownBy(() -> {
                qm.synchronizeVulnerableSoftware(vulnerability, List.of(vs1Copy, vs2Copy), Vulnerability.Source.NVD);
            });
        }

        // Verify only 2 attributions exist (one per VulnerableSoftware)
        final Vulnerability persistedVuln = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2024-0001", true);
        assertThat(persistedVuln.getVulnerableSoftware()).hasSize(2);

        final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(
                persistedVuln,
                persistedVuln.getVulnerableSoftware()
        );
        assertThat(attributions).hasSize(2);
        assertThat(attributions).extracting(AffectedVersionAttribution::getSource)
                .containsOnly(Vulnerability.Source.NVD);
    }
}

