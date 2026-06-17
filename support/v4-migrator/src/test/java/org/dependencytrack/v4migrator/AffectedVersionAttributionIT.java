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
 * Asserts AFFECTEDVERSIONATTRIBUTION migration: v4 IDs are preserved, the UUID column is
 * dropped (schema-changes §6), and rows pointing at a malformed-UUID VULNERABILITY or
 * VULNERABLESOFTWARE are dropped via the INNER JOINs through the canonical-id maps.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AffectedVersionAttributionIT {

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
    void migratesAttributionDroppingUuidAndOrphanRefs() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (1, '00000000-0000-0000-0000-000000000001', 'CVE-2024-0001', 'NVD', 'HIGH')
                """);
            // Malformed-UUID vuln; rows referencing it must be dropped.
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (2, 'not-a-uuid', 'CVE-2024-0002', 'NVD', 'LOW')
                """);
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" ("ID", "UUID", "VULNERABLE")
                VALUES (10, '00000000-0000-0000-0000-00000000000a', TRUE)
                """);
            // Junction reference required: orphan VS rows are dropped per spec.
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                VALUES (1, 10)
                """);

            h.execute("""
                INSERT INTO "AFFECTEDVERSIONATTRIBUTION" (
                    "ID", "FIRST_SEEN", "LAST_SEEN", "SOURCE", "UUID",
                    "VULNERABILITY", "VULNERABLE_SOFTWARE"
                )
                VALUES (
                    100, '2024-01-01T00:00:00Z', '2024-12-01T00:00:00Z', 'NVD',
                    '00000000-0000-0000-0000-000000000abc', 1, 10
                )
                """);
            // Orphan: references the malformed-UUID vuln (2).
            h.execute("""
                INSERT INTO "AFFECTEDVERSIONATTRIBUTION" (
                    "ID", "FIRST_SEEN", "LAST_SEEN", "SOURCE", "UUID",
                    "VULNERABILITY", "VULNERABLE_SOFTWARE"
                )
                VALUES (
                    101, '2024-01-01T00:00:00Z', '2024-12-01T00:00:00Z', 'NVD',
                    '00000000-0000-0000-0000-000000000abd', 2, 10
                )
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "SOURCE", "VULNERABILITY", "VULNERABLE_SOFTWARE"
                      FROM "AFFECTEDVERSIONATTRIBUTION"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("id", 100L)
            .containsEntry("source", "NVD")
            .containsEntry("vulnerability", 1L)
            .containsEntry("vulnerable_software", 10L);

        // v5 table has no UUID column; selecting it must fail.
        final List<String> columns = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT column_name
                      FROM information_schema.columns
                     WHERE table_name = 'AFFECTEDVERSIONATTRIBUTION'
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
