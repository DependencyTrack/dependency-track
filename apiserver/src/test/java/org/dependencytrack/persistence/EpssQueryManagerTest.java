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
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.persistence.jdbi.EpssDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class EpssQueryManagerTest extends PersistenceCapableTest {

    @Test
    void shouldReturnDirectEpssForCveSourcedVuln() {
        persistEpss("CVE-000", "0.01", "0.02");

        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.NVD.name(), "CVE-000"))
                .isNotNull()
                .satisfies(e -> {
                    assertThat(e.getCve()).isEqualTo("CVE-000");
                    assertThat(e.getScore()).isEqualByComparingTo("0.01");
                    assertThat(e.getPercentile()).isEqualByComparingTo("0.02");
                });
    }

    @Test
    void shouldReturnNullWhenVulnHasNoCveAndNoAlias() {
        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.GITHUB.name(), "GHSA-xxxx-yyyy-zzzz")).isNull();
        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.NVD.name(), "CVE-MISSING")).isNull();
    }

    @Test
    void shouldReturnEpssForAliasedVuln() {
        persistEpss("CVE-100", "0.42", "0.88");
        linkAliases(
                new VulnerabilityKey("CVE-100", "NVD"),
                Set.of(new VulnerabilityKey("GHSA-aaaa-bbbb-cccc", "GITHUB")));

        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.GITHUB.name(), "GHSA-aaaa-bbbb-cccc"))
                .isNotNull()
                .satisfies(e -> {
                    assertThat(e.getCve()).isEqualTo("CVE-100");
                    assertThat(e.getScore()).isEqualByComparingTo("0.42");
                    assertThat(e.getPercentile()).isEqualByComparingTo("0.88");
                });
    }

    @Test
    void shouldReturnMostImpactfulEpssWhenAliasedToMultipleCves() {
        persistEpss("CVE-200", "0.10", "0.20");
        persistEpss("CVE-201", "0.90", "0.50");
        persistEpss("CVE-202", "0.30", "0.40");
        linkAliases(
                new VulnerabilityKey("CVE-200", "NVD"),
                Set.of(
                        new VulnerabilityKey("CVE-201", "NVD"),
                        new VulnerabilityKey("CVE-202", "NVD"),
                        new VulnerabilityKey("GHSA-multi-cve-test", "GITHUB")));

        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.GITHUB.name(), "GHSA-multi-cve-test"))
                .isNotNull()
                .satisfies(e -> {
                    assertThat(e.getCve()).isEqualTo("CVE-201");
                    assertThat(e.getScore()).isEqualByComparingTo("0.90");
                });
    }

    @Test
    void shouldBreakScoreTiesByPercentileThenByCveAscending() {
        persistEpss("CVE-301", "0.50", "0.20");
        persistEpss("CVE-302", "0.50", "0.80");
        persistEpss("CVE-303", "0.50", "0.80");
        linkAliases(
                new VulnerabilityKey("CVE-301", "NVD"),
                Set.of(
                        new VulnerabilityKey("CVE-302", "NVD"),
                        new VulnerabilityKey("CVE-303", "NVD"),
                        new VulnerabilityKey("GHSA-tie-test", "GITHUB")));

        assertThat(qm.getEffectiveEpssForVuln(Vulnerability.Source.GITHUB.name(), "GHSA-tie-test"))
                .isNotNull()
                .satisfies(e -> assertThat(e.getCve()).isEqualTo("CVE-302"));
    }

    @Test
    void shouldReturnBatchKeyedBySourceAndVulnId() {
        persistEpss("CVE-400", "0.10", "0.10");
        persistEpss("CVE-401", "0.20", "0.20");
        linkAliases(
                new VulnerabilityKey("CVE-401", "NVD"),
                Set.of(new VulnerabilityKey("GHSA-batch-test", "GITHUB")));

        final var result = qm.getEffectiveEpssForVulns(List.of(
                new VulnerabilityKey("CVE-400", "NVD"),
                new VulnerabilityKey("GHSA-batch-test", "GITHUB"),
                new VulnerabilityKey("GHSA-missing", "GITHUB")));

        assertThat(result).hasSize(2);
        assertThat(result.get(new VulnerabilityKey("CVE-400", "NVD"))).satisfies(e ->
                assertThat(e.getScore()).isEqualByComparingTo("0.10"));
        assertThat(result.get(new VulnerabilityKey("GHSA-batch-test", "GITHUB"))).satisfies(e ->
                assertThat(e.getCve()).isEqualTo("CVE-401"));
    }

    @Test
    void shouldReturnEmptyMapForEmptyBatch() {
        assertThat(qm.getEffectiveEpssForVulns(List.of())).isEmpty();
    }

    private void persistEpss(final String cve, final String score, final String percentile) {
        useJdbiHandle(handle -> handle.attach(EpssDao.class)
                .createOrUpdateAll(List.of(new Epss(cve, new BigDecimal(score), new BigDecimal(percentile)))));
    }

    private void linkAliases(final VulnerabilityKey vulnKey, final Set<VulnerabilityKey> aliasKeys) {
        useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                .syncAssertions("test", Map.of(vulnKey, aliasKeys)));
    }
}
