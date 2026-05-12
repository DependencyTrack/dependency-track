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
 * Asserts §4.8 (natural-key dedup with LAST_BOM_IMPORTED tiebreaker) and §4.9
 * (one IS_LATEST per NAME) for PROJECT.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectDedupIT {

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
    void collapsesDuplicateProjectsAndPicksOneIsLatestPerName() throws Exception {
        source.jdbi().useHandle(h -> {
            // Three rows under ("Foo", "1.0") with different LAST_BOM_IMPORTED.
            // Canonical winner = ID 3 (newest LAST_BOM_IMPORTED).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED", "IS_LATEST")
                VALUES (1, 'Foo', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z', TRUE)
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED", "IS_LATEST")
                VALUES (2, 'Foo', '1.0', '00000000-0000-0000-0000-000000000002',
                        '2024-06-01T00:00:00Z', TRUE)
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED", "IS_LATEST")
                VALUES (3, 'Foo', '1.0', '00000000-0000-0000-0000-000000000003',
                        '2024-12-01T00:00:00Z', TRUE)
                """);
            // Different VERSION under same NAME; both IS_LATEST=TRUE. §4.9: only the
            // newest LAST_BOM_IMPORTED across all canonicals for NAME='Foo' should win.
            // Above row 3 ('1.0', 2024-12-01) beats row 10 ('2.0', 2024-09-01).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED", "IS_LATEST")
                VALUES (10, 'Foo', '2.0', '00000000-0000-0000-0000-000000000010',
                        '2024-09-01T00:00:00Z', TRUE)
                """);
            // Unrelated NAME with no IS_LATEST=TRUE in v4: stays FALSE.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED", "IS_LATEST")
                VALUES (20, 'Bar', '1.0', '00000000-0000-0000-0000-000000000020',
                        '2024-05-01T00:00:00Z', FALSE)
                """);
        });

        runPipeline();

        // canonical_id_map: all three Foo/1.0 rows map to 3; Foo/2.0 maps to 10; Bar/1.0 maps to 20.
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.project_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id").containsExactly(
            tuple(1L, 3L),
            tuple(2L, 3L),
            tuple(3L, 3L),
            tuple(10L, 10L),
            tuple(20L, 20L)
        );

        // v5 PROJECT: only canonicals (3, 10, 20). IS_LATEST=TRUE on (3) only.
        final List<Map<String, Object>> projects = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "VERSION", "IS_LATEST"
                      FROM "PROJECT"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(projects).extracting("id", "name", "version", "is_latest").containsExactly(
            tuple(3L, "Foo", "1.0", true),
            tuple(10L, "Foo", "2.0", false),
            tuple(20L, "Bar", "1.0", false)
        );
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
