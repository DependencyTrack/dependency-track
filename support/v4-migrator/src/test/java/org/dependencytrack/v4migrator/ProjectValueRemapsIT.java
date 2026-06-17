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
 * Asserts PROJECT value transforms: §5.1 CLASSIFIER coerce, §5.2 COLLECTION_LOGIC NONE
 * coerce + COLLECTION_TAG → COLLECTION_TAG_ID rewire, §5.3 CLASSIFIER/COLLECTION_LOGIC
 * mutual exclusivity, §6.2 DIRECT_DEPENDENCIES text → JSONB.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectValueRemapsIT {

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
    void appliesAllValueTransforms() throws Exception {
        source.jdbi().useHandle(h -> {
            // A TAG referenced by PROJECT.COLLECTION_TAG. v5 stores its canonical id.
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (42, 'collection-target')");

            // Row 1: CLASSIFIER='LIBRARY' preserved.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "UUID", "CLASSIFIER", "DIRECT_DEPENDENCIES")
                VALUES (1, 'P-Lib', '00000000-0000-0000-0000-000000000001',
                        'LIBRARY', '[{"ref":"abc"}]')
                """);
            // Row 2: CLASSIFIER='NONE' → NULL; DIRECT_DEPENDENCIES malformed → NULL.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "UUID", "CLASSIFIER", "DIRECT_DEPENDENCIES")
                VALUES (2, 'P-None', '00000000-0000-0000-0000-000000000002',
                        'NONE', 'not json')
                """);
            // Row 4: both CLASSIFIER and COLLECTION_LOGIC non-null → CLASSIFIER NULLed (§5.3);
            // COLLECTION_TAG rewires to v5 COLLECTION_TAG_ID via tag_canonical_id_map.
            h.execute("""
                INSERT INTO "PROJECT" (
                    "ID", "NAME", "UUID", "CLASSIFIER", "COLLECTION_LOGIC", "COLLECTION_TAG"
                )
                VALUES (4, 'P-Both', '00000000-0000-0000-0000-000000000004',
                        'LIBRARY', 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG', 42)
                """);
            // Row 5: COLLECTION_LOGIC='NONE' coerces to NULL (§5.2).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "UUID", "COLLECTION_LOGIC")
                VALUES (5, 'P-LogicNone', '00000000-0000-0000-0000-000000000005', 'NONE')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "CLASSIFIER", "COLLECTION_LOGIC",
                           "COLLECTION_TAG_ID", "DIRECT_DEPENDENCIES"::text AS dd_text
                      FROM "PROJECT"
                     ORDER BY "ID"
                    """).mapToMap().list());

        assertThat(rows).hasSize(4);

        assertThat(rows.get(0))
            .containsEntry("name", "P-Lib")
            .containsEntry("classifier", "LIBRARY")
            .containsEntry("collection_logic", null)
            .containsEntry("collection_tag_id", null);
        assertThat(rows.get(0).get("dd_text")).asString().contains("\"ref\"").contains("abc");

        assertThat(rows.get(1))
            .containsEntry("name", "P-None")
            .containsEntry("classifier", null)
            .containsEntry("dd_text", null);

        assertThat(rows.get(2))
            .containsEntry("name", "P-Both")
            .containsEntry("classifier", null)
            .containsEntry("collection_logic", "AGGREGATE_DIRECT_CHILDREN_WITH_TAG")
            .containsEntry("collection_tag_id", 42L);

        assertThat(rows.get(3))
            .containsEntry("name", "P-LogicNone")
            .containsEntry("collection_logic", null);

        // Sanity check the canonical_id_map exists with one entry per orig (all unique
        // (NAME, VERSION) here, so each row maps to itself).
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.project_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id").containsExactly(
            tuple(1L, 1L),
            tuple(2L, 2L),
            tuple(4L, 4L),
            tuple(5L, 5L)
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
