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
package org.dependencytrack.v4migrator;

import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.extract.ExtractPhase;
import org.dependencytrack.v4migrator.load.LoadPhase;
import org.dependencytrack.v4migrator.testsupport.V4PostgresSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Spec §"Intentional data loss": {@code VULNERABLESOFTWARE} rows not referenced by any
 * vulnerability via the {@code VULNERABLESOFTWARE_VULNERABILITIES} junction are dropped.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OrphanedVulnerableSoftwareIT {

    private V4PostgresSource source;
    private V5TargetContainer target;

    @BeforeAll
    void start() {
        source = new V4PostgresSource().start();
        target = new V5TargetContainer().start();
    }

    @AfterAll
    void stop() {
        if (source != null) {
            source.close();
        }
        if (target != null) {
            target.close();
        }
    }

    @Test
    void dropsVulnerableSoftwareNotReferencedByJunction() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (1, '00000000-0000-0000-0000-000000000001', 'CVE-2024-0001', 'NVD', 'HIGH')
                """);
            // Referenced VS: present in junction; must survive.
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" ("ID", "UUID", "PART", "VULNERABLE")
                VALUES (10, '00000000-0000-0000-0000-00000000000a', 'a', TRUE)
                """);
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES"
                    ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                VALUES (1, 10)
                """);
            // Orphan VS: valid UUID, but no junction reference; must be dropped.
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" ("ID", "UUID", "PART", "VULNERABLE")
                VALUES (11, '00000000-0000-0000-0000-00000000000b', 'a', FALSE)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.vulnerablesoftware_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map)
            .as("orphan VS (id=11) must be excluded from the canonical map")
            .extracting("orig_id", "canonical_id")
            .containsExactly(tuple(10L, 10L));

        final List<Long> vsIds = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"ID\" FROM \"VULNERABLESOFTWARE\" ORDER BY \"ID\"")
                .mapTo(Long.class)
                .list());
        assertThat(vsIds)
            .as("orphan VS (id=11) must not be loaded into v5")
            .containsExactly(10L);

        final List<Map<String, Object>> joins = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
                      FROM "VULNERABLESOFTWARE_VULNERABILITIES"
                     ORDER BY "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
                    """).mapToMap().list());
        assertThat(joins)
            .extracting("vulnerability_id", "vulnerablesoftware_id")
            .containsExactly(tuple(1L, 10L));
    }

    private void runPipeline() throws Exception {
        final GlobalOptions global = new GlobalOptions();
        global.targetUrl = target.jdbcUrl();
        global.targetUser = target.username();
        global.targetPass = target.password();
        global.stagingSchema = "dt_v4_migration";
        global.logLevel = "INFO";

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = source.jdbcUrl();
        src.sourceUser = source.username();
        src.sourcePass = source.password();

        new ExtractPhase(global, src, target.jdbi(), 90).run();
        new TransformPhase(global, target.jdbi()).run();
        new LoadPhase(global, target.jdbi(), false).run();
    }
}
