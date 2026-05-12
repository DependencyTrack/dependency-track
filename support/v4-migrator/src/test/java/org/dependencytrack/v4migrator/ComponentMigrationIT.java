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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Asserts COMPONENT migration: CLASSIFIER='NONE' coerce to NULL (§5.1), UUID conversion + probe
 * (§6.1), DIRECT_DEPENDENCIES text → JSONB (§6.2), PROJECT_ID rewrite through
 * {@code project_canonical_id_map}, PARENT_COMPONENT_ID rewrite through
 * {@code component_canonical_id_map} (orphan tolerance), pass-through columns
 * (SCOPE, hashes, EXTERNAL_REFERENCES bytes, PURL).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ComponentMigrationIT {

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
    void migratesComponentsWithCoerceProbeAndIdRewires() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two PROJECTs sharing NAME so PROJECT dedup picks a winner.
            // Per §4.8 (LAST_BOM_IMPORTED DESC NULLS LAST, ID DESC), winner = ID 200.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (100, 'P', '1.0', '00000000-0000-0000-0000-000000000100',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (200, 'P', '1.0', '00000000-0000-0000-0000-000000000200',
                        '2024-06-01T00:00:00Z')
                """);

            // Good parent component on the canonical project (200).
            h.createUpdate("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "CLASSIFIER",
                    "DIRECT_DEPENDENCIES", "SCOPE", "SHA_256", "PURL",
                    "EXTERNAL_REFERENCES"
                )
                VALUES (
                    1, 'parent', :u, 200, 'LIBRARY',
                    '[{"ref":"x"}]', 'REQUIRED',
                    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
                    'pkg:maven/g/a@1', :ext
                )
                """)
                .bind("u", "00000000-0000-0000-0000-000000000001")
                .bind("ext", new byte[]{0x01, 0x02, 0x03})
                .execute();

            // Child of (1). Points at the LOSER project (100); should be rewritten to 200.
            h.execute("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "PARENT_COMPONENT_ID", "CLASSIFIER"
                )
                VALUES (
                    2, 'child', '00000000-0000-0000-0000-000000000002', 100, 1, 'APPLICATION'
                )
                """);

            // CLASSIFIER='NONE' → NULL.
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "UUID", "PROJECT_ID", "CLASSIFIER")
                VALUES (3, 'c-none', '00000000-0000-0000-0000-000000000003', 200, 'NONE')
                """);

            // Malformed UUID: probed and excluded from v5.
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "UUID", "PROJECT_ID")
                VALUES (5, 'c-bad-uuid', 'not-a-uuid', 200)
                """);

            // Orphaned PARENT_COMPONENT_ID: parent (5) has a malformed UUID and is not
            // in component_canonical_id_map. Child must survive with PARENT_COMPONENT_ID NULL.
            h.execute("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "PARENT_COMPONENT_ID"
                )
                VALUES (6, 'c-orphan', '00000000-0000-0000-0000-000000000006', 200, 5)
                """);

            // Malformed DIRECT_DEPENDENCIES → NULL in v5 (row kept).
            h.execute("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "DIRECT_DEPENDENCIES"
                )
                VALUES (
                    7, 'c-bad-json', '00000000-0000-0000-0000-000000000007', 200, 'not json'
                )
                """);
        });

        runPipeline();

        // Malformed UUID probed.
        final List<Map<String, Object>> probe = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, bad_uuid
                      FROM "dt_v4_migration".probe_invalid_uuids
                     WHERE table_name = 'COMPONENT'
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(probe).hasSize(1);
        assertThat(probe.get(0))
            .containsEntry("table_name", "COMPONENT")
            .containsEntry("orig_id", 5L)
            .containsEntry("bad_uuid", "not-a-uuid");

        // identity component_canonical_id_map for valid-UUID rows.
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.component_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id").containsExactly(
            tuple(1L, 1L),
            tuple(2L, 2L),
            tuple(3L, 3L),
            tuple(6L, 6L),
            tuple(7L, 7L)
        );

        // Full v5 COMPONENT contents.
        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "UUID", "CLASSIFIER", "SCOPE",
                           "PROJECT_ID", "PARENT_COMPONENT_ID", "SHA_256", "PURL",
                           "EXTERNAL_REFERENCES",
                           "DIRECT_DEPENDENCIES"::text AS dd_text
                      FROM "COMPONENT"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(5);

        // (1) parent: full pass-through, PROJECT_ID stays at canonical 200, native UUID.
        assertThat(rows.get(0))
            .containsEntry("name", "parent")
            .containsEntry("uuid", UUID.fromString("00000000-0000-0000-0000-000000000001"))
            .containsEntry("classifier", "LIBRARY")
            .containsEntry("scope", "REQUIRED")
            .containsEntry("project_id", 200L)
            .containsEntry("parent_component_id", null)
            .containsEntry("sha_256", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            .containsEntry("purl", "pkg:maven/g/a@1");
        assertThat((byte[]) rows.get(0).get("external_references"))
            .containsExactly(0x01, 0x02, 0x03);
        assertThat(rows.get(0).get("dd_text")).asString().contains("\"ref\"").contains("x");

        // (2) child: PROJECT_ID rewritten from loser (100) to winner (200);
        // PARENT_COMPONENT_ID preserved.
        assertThat(rows.get(1))
            .containsEntry("name", "child")
            .containsEntry("project_id", 200L)
            .containsEntry("parent_component_id", 1L)
            .containsEntry("classifier", "APPLICATION");

        // (3) CLASSIFIER='NONE' → NULL.
        assertThat(rows.get(2))
            .containsEntry("name", "c-none")
            .containsEntry("classifier", null);

        // (6) Orphan: parent had malformed UUID → PARENT_COMPONENT_ID NULL, child survives.
        assertThat(rows.get(3))
            .containsEntry("name", "c-orphan")
            .containsEntry("parent_component_id", null);

        // (7) Malformed DIRECT_DEPENDENCIES → NULL.
        assertThat(rows.get(4))
            .containsEntry("name", "c-bad-json")
            .containsEntry("dd_text", null);
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
