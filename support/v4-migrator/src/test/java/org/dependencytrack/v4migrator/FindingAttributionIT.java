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

/**
 * Asserts FINDINGATTRIBUTION migration: 3-column dedup on
 * {@code (COMPONENT_ID, VULNERABILITY_ID, ANALYZERIDENTITY)} keeping the newest
 * {@code ATTRIBUTED_ON}, value-remap of {@code ANALYZERIDENTITY} per schema-changes §5.6,
 * drop of the {@code UUID} column (§6), and NULL-fill of the additive {@code MATCHING_PERCENTAGE}
 * and {@code DELETED_AT} columns.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindingAttributionIT {

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
    void migratesFindingAttributionWithDedupRemapAndDroppedUuid() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "PROJECT_ID", "UUID")
                VALUES (10, 'lib', 1, '00000000-0000-0000-0000-00000000000a')
                """);
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (100, '00000000-0000-0000-0000-000000000064', 'CVE-2024-0001', 'NVD', 'HIGH')
                """);
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (101, '00000000-0000-0000-0000-000000000065', 'CVE-2024-0002', 'NVD', 'LOW')
                """);

            // Two rows on the same (component, vuln, analyzer) key; keep the newer (id=2).
            h.execute("""
                INSERT INTO "FINDINGATTRIBUTION" (
                    "ID", "ANALYZERIDENTITY", "ATTRIBUTED_ON", "COMPONENT_ID",
                    "PROJECT_ID", "REFERENCE_URL", "UUID", "VULNERABILITY_ID"
                )
                VALUES (
                    1, 'OSSINDEX_ANALYZER', '2024-01-01T00:00:00Z', 10, 1,
                    'https://example.org/older',
                    '00000000-0000-0000-0000-0000000000aa', 100
                )
                """);
            h.execute("""
                INSERT INTO "FINDINGATTRIBUTION" (
                    "ID", "ANALYZERIDENTITY", "ATTRIBUTED_ON", "COMPONENT_ID",
                    "PROJECT_ID", "REFERENCE_URL", "UUID", "VULNERABILITY_ID"
                )
                VALUES (
                    2, 'OSSINDEX_ANALYZER', '2024-06-01T00:00:00Z', 10, 1,
                    'https://example.org/newer',
                    '00000000-0000-0000-0000-0000000000ab', 100
                )
                """);
            // Different vuln; survives. Uses SNYK_ANALYZER to assert remap.
            h.execute("""
                INSERT INTO "FINDINGATTRIBUTION" (
                    "ID", "ANALYZERIDENTITY", "ATTRIBUTED_ON", "COMPONENT_ID",
                    "PROJECT_ID", "REFERENCE_URL", "UUID", "VULNERABILITY_ID"
                )
                VALUES (
                    3, 'SNYK_ANALYZER', '2024-03-01T00:00:00Z', 10, 1,
                    'https://snyk.io/x',
                    '00000000-0000-0000-0000-0000000000ac', 101
                )
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "ANALYZERIDENTITY", "COMPONENT_ID", "VULNERABILITY_ID",
                           "REFERENCE_URL", "MATCHING_PERCENTAGE", "DELETED_AT"
                      FROM "FINDINGATTRIBUTION"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0))
            .containsEntry("id", 2L)
            .containsEntry("analyzeridentity", "oss-index")
            .containsEntry("component_id", 10L)
            .containsEntry("vulnerability_id", 100L)
            .containsEntry("reference_url", "https://example.org/newer")
            .containsEntry("matching_percentage", null)
            .containsEntry("deleted_at", null);
        assertThat(rows.get(1))
            .containsEntry("id", 3L)
            .containsEntry("analyzeridentity", "snyk")
            .containsEntry("component_id", 10L)
            .containsEntry("vulnerability_id", 101L);

        // v5 has no UUID column on FINDINGATTRIBUTION.
        final List<String> columns = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT column_name
                      FROM information_schema.columns
                     WHERE table_name = 'FINDINGATTRIBUTION'
                    """).mapTo(String.class).list());
        assertThat(columns).doesNotContain("UUID");
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
