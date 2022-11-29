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

import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.dependencytrack.parser.github.graphql.model.GitHubVulnerability;
import org.junit.Test;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class GitHubAdvisoryMirrorTaskTest extends PersistenceCapableTest {

    @Test
    public void testUpdateDatasource() {
        final var ghVuln1 = new GitHubVulnerability();
        ghVuln1.setPackageEcosystem("maven");
        ghVuln1.setPackageName("com.fasterxml.jackson.core:jackson-databind");
        ghVuln1.setVulnerableVersionRange(">=2.13.0,<=2.13.2.0");

        final var ghVuln2 = new GitHubVulnerability();
        ghVuln2.setPackageEcosystem("maven");
        ghVuln2.setPackageName("com.fasterxml.jackson.core:jackson-databind");
        ghVuln2.setVulnerableVersionRange("<=2.12.6.0");

        final var ghAdvisory = new GitHubSecurityAdvisory();
        ghAdvisory.setId("GHSA-57j2-w4cx-62h2");
        ghAdvisory.setGhsaId("GHSA-57j2-w4cx-62h2");
        ghAdvisory.setIdentifiers(List.of(Pair.of("CVE", "CVE-2020-36518")));
        ghAdvisory.setSeverity("HIGH");
        ghAdvisory.setVulnerabilities(List.of(ghVuln1, ghVuln2));
        ghAdvisory.setPublishedAt(ZonedDateTime.of(2022, 3, 12, 0, 0, 0, 0, ZoneOffset.UTC));
        ghAdvisory.setUpdatedAt(ZonedDateTime.of(2022, 8, 11, 0, 0, 0, 0, ZoneOffset.UTC));

        final var task = new GitHubAdvisoryMirrorTask();
        task.updateDatasource(List.of(ghAdvisory));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(vuln.getPublished()).isEqualToIgnoringHours("2022-03-12");
        assertThat(vuln.getUpdated()).isEqualToIgnoringHours("2022-08-11");

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vuln);
        assertThat(aliases).satisfiesExactly(
                alias -> {
                    assertThat(alias.getCveId()).isEqualTo("CVE-2020-36518");
                    assertThat(alias.getGhsaId()).isEqualTo("GHSA-57j2-w4cx-62h2");
                }
        );

        final List<VulnerableSoftware> vsList = vuln.getVulnerableSoftware();
        assertThat(vsList).hasSize(2);
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
        vs2.setVersionEndExcluding("2.12.6.1");
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
        existingVuln.setSource(Source.GITHUB);
        existingVuln.setVulnerableSoftware(List.of(vs1, vs2, vs3));
        existingVuln = qm.createVulnerability(existingVuln, false);
        qm.updateAffectedVersionAttribution(existingVuln, vs1, Source.OSV);
        qm.updateAffectedVersionAttribution(existingVuln, vs2, Source.OSV);
        qm.updateAffectedVersionAttribution(existingVuln, vs3, Source.GITHUB);

        // Create a vulnerable version range that is equal to vs1.
        final var ghVuln1 = new GitHubVulnerability();
        ghVuln1.setPackageEcosystem("maven");
        ghVuln1.setPackageName("com.fasterxml.jackson.core:jackson-databind");
        ghVuln1.setVulnerableVersionRange(">=2.13.0,<=2.13.2.0");

        // Create a vulnerable version range that is only differs slightly from vs2.
        final var ghVuln2 = new GitHubVulnerability();
        ghVuln2.setPackageEcosystem("maven");
        ghVuln2.setPackageName("com.fasterxml.jackson.core:jackson-databind");
        ghVuln2.setVulnerableVersionRange("<=2.12.6.0");

        // No vulnerable version range matching vs3 is created.
        // Because vs3 was attributed to GitHub, the association with the vulnerability
        // should be removed in the mirroring process.

        final var ghAdvisory = new GitHubSecurityAdvisory();
        ghAdvisory.setId("GHSA-57j2-w4cx-62h2");
        ghAdvisory.setGhsaId("GHSA-57j2-w4cx-62h2");
        ghAdvisory.setIdentifiers(List.of(Pair.of("CVE", "CVE-2020-36518")));
        ghAdvisory.setSeverity("HIGH");
        ghAdvisory.setVulnerabilities(List.of(ghVuln1, ghVuln2));
        ghAdvisory.setPublishedAt(ZonedDateTime.of(2022, 3, 12, 0, 0, 0, 0, ZoneOffset.UTC));
        ghAdvisory.setUpdatedAt(ZonedDateTime.of(2022, 8, 11, 0, 0, 0, 0, ZoneOffset.UTC));

        // Run the mirror task
        final var task = new GitHubAdvisoryMirrorTask();
        task.updateDatasource(List.of(ghAdvisory));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId(Source.GITHUB, "GHSA-57j2-w4cx-62h2");
        assertThat(vuln).isNotNull();

        final List<VulnerableSoftware> vsList = vuln.getVulnerableSoftware();
        assertThat(vsList).satisfiesExactlyInAnyOrder(
                // The version range reported by both GitHub and another source
                // must have attributions for both sources.
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
                    assertThat(attributions).satisfiesExactlyInAnyOrder(
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.OSV),
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.GITHUB)
                    );
                },
                // The version range newly reported by GitHub must be attributed to only GitHub.
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
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.GITHUB)
                    );
                },
                // The version range that was reported by another source must be retained.
                // There must be no attribution to GitHub for this range.
                vs -> {
                    assertThat(vs.getPurlType()).isEqualTo("maven");
                    assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.jackson.core");
                    assertThat(vs.getPurlName()).isEqualTo("jackson-databind");
                    assertThat(vs.getPurlVersion()).isNull();
                    assertThat(vs.getVersion()).isNull();
                    assertThat(vs.getVersionStartIncluding()).isNull();
                    assertThat(vs.getVersionStartExcluding()).isNull();
                    assertThat(vs.getVersionEndIncluding()).isNull();
                    assertThat(vs.getVersionEndExcluding()).isEqualTo("2.12.6.1");

                    final List<AffectedVersionAttribution> attributions = qm.getAffectedVersionAttributions(vuln, vs);
                    assertThat(attributions).satisfiesExactly(
                            attr -> assertThat(attr.getSource()).isEqualTo(Source.OSV)
                    );
                }
        );
    }

}