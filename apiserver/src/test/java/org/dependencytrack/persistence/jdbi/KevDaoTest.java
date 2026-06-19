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

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.model.VulnerabilityKey;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class KevDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private KevDao kevDao;

    @BeforeEach
    void beforeEach() {
        jdbiHandle = openJdbiHandle();
        kevDao = jdbiHandle.attach(KevDao.class);
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @Test
    void shouldReconcileUpdatesAndDeletions() {
        kevDao.upsertBatch("cisa", List.of(
                new KevAssertion(
                        "NVD",
                        "CVE-1",
                        null,
                        "action-a",
                        false,
                        "desc-a",
                        JsonNodeFactory.instance.objectNode().put("v", 1)),
                new KevAssertion(
                        "NVD",
                        "CVE-2",
                        null,
                        null,
                        null,
                        null,
                        JsonNodeFactory.instance.objectNode())));

        final var current = List.of(
                new KevAssertion(
                        "NVD",
                        "CVE-1",
                        null,
                        "action-b",
                        true,
                        "desc-b",
                        JsonNodeFactory.instance.objectNode().put("v", 2)),
                new KevAssertion(
                        "NVD",
                        "CVE-3",
                        null,
                        null,
                        null,
                        null,
                        JsonNodeFactory.instance.objectNode()));
        kevDao.upsertBatch("cisa", current);
        kevDao.deleteStale("cisa", vulnKeysOf(current));

        assertThat(jdbiHandle.createQuery("""
                        SELECT "VULN_ID"
                          FROM "KEV_ASSERTION"
                         WHERE "ASSERTER" = 'cisa'
                         ORDER BY "VULN_ID"
                        """)
                .mapTo(String.class)
                .list())
                .containsExactly("CVE-1", "CVE-3");
        assertThat(jdbiHandle.createQuery("""
                        SELECT "REQUIRED_ACTION"
                          FROM "KEV_ASSERTION"
                         WHERE "VULN_ID" = 'CVE-1'
                        """)
                .mapTo(String.class)
                .one())
                .isEqualTo("action-b");
    }

    @Test
    void shouldNotTouchUpdatedAtWhenUnchanged() {
        final var assertions = List.of(
                new KevAssertion(
                        "NVD",
                        "CVE-1",
                        null,
                        "action",
                        false,
                        "desc",
                        JsonNodeFactory.instance.objectNode().put("v", 1)));
        kevDao.upsertBatch("cisa", assertions);
        final Instant firstUpdatedAt = getUpdatedAt("CVE-1");

        kevDao.upsertBatch("cisa", assertions);
        assertThat(getUpdatedAt("CVE-1")).isEqualTo(firstUpdatedAt);
    }

    @Test
    void shouldKeepAssertionsOfOtherAssertersSeparate() {
        kevDao.upsertBatch("cisa", List.of(
                new KevAssertion(
                        "NVD",
                        "CVE-1",
                        null,
                        null,
                        null,
                        null,
                        JsonNodeFactory.instance.objectNode())));
        kevDao.upsertBatch("enisa", List.of(
                new KevAssertion(
                        "NVD",
                        "CVE-1",
                        null,
                        null,
                        null,
                        null,
                        JsonNodeFactory.instance.objectNode())));

        kevDao.deleteStale("cisa", List.of());

        assertThat(countKevAssertions("cisa")).isZero();
        assertThat(countKevAssertions("enisa")).isEqualTo(1);
    }

    private static List<VulnerabilityKey> vulnKeysOf(Collection<KevAssertion> assertions) {
        return assertions.stream()
                .map(assertion -> new VulnerabilityKey(
                        assertion.vulnId(),
                        assertion.vulnSource()))
                .toList();
    }

    private int countKevAssertions(String asserter) {
        return jdbiHandle.createQuery("""
                        SELECT COUNT(*)
                          FROM "KEV_ASSERTION"
                         WHERE "ASSERTER" = :asserter
                        """)
                .bind("asserter", asserter)
                .mapTo(Integer.class)
                .one();
    }

    private Instant getUpdatedAt(String vulnId) {
        return jdbiHandle.createQuery("""
                        SELECT "UPDATED_AT"
                          FROM "KEV_ASSERTION"
                         WHERE "VULN_ID" = :vulnId
                        """)
                .bind("vulnId", vulnId)
                .mapTo(Instant.class)
                .one();
    }

}
