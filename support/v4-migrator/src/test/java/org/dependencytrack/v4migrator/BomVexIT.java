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
 * Asserts BOM and VEX migration: native UUID conversion, malformed-UUID rows are probed
 * and excluded, PROJECT_ID is rewritten through the canonical-id map, and the additive v5
 * {@code GENERATED} column on BOM is NULL-filled.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class BomVexIT {

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
    void migratesBomAndVexProbingMalformedUuids() throws Exception {
        final UUID bomUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        final UUID vexUuid = UUID.fromString("22222222-2222-2222-2222-222222222222");
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);

            h.createUpdate("""
                INSERT INTO "BOM" (
                    "ID", "BOM_FORMAT", "BOM_VERSION", "IMPORTED", "PROJECT_ID",
                    "SERIAL_NUMBER", "SPEC_VERSION", "UUID"
                )
                VALUES (10, 'CycloneDX', 1, '2024-06-01T00:00:00Z', 1,
                        'urn:uuid:abc', '1.5', :u)
                """).bind("u", bomUuid.toString()).execute();
            h.execute("""
                INSERT INTO "BOM" (
                    "ID", "BOM_FORMAT", "BOM_VERSION", "IMPORTED", "PROJECT_ID",
                    "SERIAL_NUMBER", "SPEC_VERSION", "UUID"
                )
                VALUES (11, 'CycloneDX', 1, '2024-06-01T00:00:00Z', 1,
                        'urn:uuid:bad', '1.5', 'not-a-uuid')
                """);

            h.createUpdate("""
                INSERT INTO "VEX" (
                    "ID", "IMPORTED", "PROJECT_ID", "SERIAL_NUMBER", "SPEC_VERSION",
                    "UUID", "VEX_FORMAT", "VEX_VERSION"
                )
                VALUES (20, '2024-06-01T00:00:00Z', 1, 'urn:uuid:xyz', '1.5',
                        :u, 'CycloneDX', 1)
                """).bind("u", vexUuid.toString()).execute();
            h.execute("""
                INSERT INTO "VEX" (
                    "ID", "IMPORTED", "PROJECT_ID", "SERIAL_NUMBER", "SPEC_VERSION",
                    "UUID", "VEX_FORMAT", "VEX_VERSION"
                )
                VALUES (21, '2024-06-01T00:00:00Z', 1, 'urn:uuid:badvex', '1.5',
                        'not-a-uuid', 'CycloneDX', 1)
                """);
        });

        runPipeline();

        // Malformed UUIDs landed in the probe.
        final List<Map<String, Object>> probe = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, bad_uuid
                      FROM "dt_v4_migration".probe_invalid_uuids
                     WHERE table_name IN ('BOM', 'VEX')
                     ORDER BY table_name, orig_id
                    """).mapToMap().list());
        assertThat(probe).extracting("table_name", "orig_id", "bad_uuid").containsExactly(
            tuple("BOM", 11L, "not-a-uuid"),
            tuple("VEX", 21L, "not-a-uuid")
        );

        final List<Map<String, Object>> boms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "BOM_FORMAT", "PROJECT_ID", "UUID", "GENERATED"
                      FROM "BOM"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(boms).hasSize(1);
        assertThat(boms.get(0))
            .containsEntry("id", 10L)
            .containsEntry("bom_format", "CycloneDX")
            .containsEntry("project_id", 1L)
            .containsEntry("uuid", bomUuid)
            .containsEntry("generated", null);

        final List<Map<String, Object>> vexes = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "VEX_FORMAT", "PROJECT_ID", "UUID"
                      FROM "VEX"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(vexes).hasSize(1);
        assertThat(vexes.get(0))
            .containsEntry("id", 20L)
            .containsEntry("vex_format", "CycloneDX")
            .containsEntry("project_id", 1L)
            .containsEntry("uuid", vexUuid);
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
