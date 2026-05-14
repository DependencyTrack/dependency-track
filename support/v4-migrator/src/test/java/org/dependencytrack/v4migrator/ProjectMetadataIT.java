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
 * Asserts §4.4 PROJECT_METADATA dedup: two v4 rows pointing at the same canonical PROJECT
 * (after PROJECT dedup) collapse to one row in v5, keeping the row with the newer v4
 * {@code ID}. AUTHORS / SUPPLIER pass through; additive {@code TOOLS} column is NULL.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectMetadataIT {

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
    void dedupsMetadataKeepingNewerIdAndNullFillsTools() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two PROJECTs collide on (NAME, VERSION). Canonical winner = ID 2 (newer LBI).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'Foo', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (2, 'Foo', '1.0', '00000000-0000-0000-0000-000000000002',
                        '2024-12-01T00:00:00Z')
                """);

            // Two metadata rows, one per v4 PROJECT, both rewrite to canonical PROJECT 2.
            h.execute("""
                INSERT INTO "PROJECT_METADATA" ("ID", "AUTHORS", "PROJECT_ID", "SUPPLIER")
                VALUES (100, '[{"name":"old"}]', 1, '{"name":"OldCo"}')
                """);
            h.execute("""
                INSERT INTO "PROJECT_METADATA" ("ID", "AUTHORS", "PROJECT_ID", "SUPPLIER")
                VALUES (200, '[{"name":"new"}]', 2, '{"name":"NewCo"}')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "PROJECT_ID", "AUTHORS", "SUPPLIER", "TOOLS"
                      FROM "PROJECT_METADATA"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("id", 200L)
            .containsEntry("project_id", 2L)
            .containsEntry("authors", "[{\"name\":\"new\"}]")
            .containsEntry("supplier", "{\"name\":\"NewCo\"}")
            .containsEntry("tools", null);
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
