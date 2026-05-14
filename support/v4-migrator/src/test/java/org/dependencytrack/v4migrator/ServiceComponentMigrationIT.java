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
 * Asserts SERVICECOMPONENT migration: UUID conversion + probe, PROJECT_ID rewrite through
 * {@code project_canonical_id_map}, PARENT_SERVICECOMPONENT_ID rewrite through
 * {@code servicecomponent_canonical_id_map} (orphan tolerance), four bytea blob pass-through,
 * and the SERVICECOMPONENTS_VULNERABILITIES join.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ServiceComponentMigrationIT {

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
    void migratesServiceComponentsWithProbeIdRewiresAndJoin() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two PROJECTs sharing NAME so PROJECT dedup picks a winner (200 wins per §4.8).
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

            // Good parent service component on the canonical project (200) with all four
            // bytea blobs populated.
            h.createUpdate("""
                INSERT INTO "SERVICECOMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "LAST_RISKSCORE",
                    "AUTHENTICATED", "X_TRUST_BOUNDARY", "DESCRIPTION", "GROUP", "VERSION",
                    "DATA", "ENDPOINTS", "EXTERNAL_REFERENCES", "PROVIDER_ID"
                )
                VALUES (
                    1, 'parent-svc', :u, 200, 1.5,
                    TRUE, FALSE, 'desc', 'g', 'v1',
                    :data, :endpoints, :ext, :provider
                )
                """)
                .bind("u", "00000000-0000-0000-0000-00000000aa01")
                .bind("data", new byte[]{0x10, 0x11, 0x12})
                .bind("endpoints", new byte[]{0x20, 0x21, 0x22})
                .bind("ext", new byte[]{0x30, 0x31, 0x32})
                .bind("provider", new byte[]{0x40, 0x41, 0x42})
                .execute();

            // Child of (1). Points at the LOSER project (100); should be rewritten to 200.
            h.execute("""
                INSERT INTO "SERVICECOMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "LAST_RISKSCORE",
                    "PARENT_SERVICECOMPONENT_ID"
                )
                VALUES (
                    2, 'child-svc', '00000000-0000-0000-0000-00000000aa02', 100, 0, 1
                )
                """);

            // Malformed UUID: probed and excluded from v5.
            h.execute("""
                INSERT INTO "SERVICECOMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "LAST_RISKSCORE"
                )
                VALUES (3, 'svc-bad-uuid', 'not-a-uuid', 200, 0)
                """);

            // Orphaned PARENT_SERVICECOMPONENT_ID: parent (3) has a malformed UUID and is
            // not in servicecomponent_canonical_id_map. Child survives with NULL parent.
            h.execute("""
                INSERT INTO "SERVICECOMPONENT" (
                    "ID", "NAME", "UUID", "PROJECT_ID", "LAST_RISKSCORE",
                    "PARENT_SERVICECOMPONENT_ID"
                )
                VALUES (
                    4, 'svc-orphan', '00000000-0000-0000-0000-00000000aa04', 200, 0, 3
                )
                """);

            // Vulnerabilities for the join: one good, one malformed-UUID (must be dropped
            // from the v5 vuln set and from the join).
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (500, '00000000-0000-0000-0000-000000000500', 'CVE-2024-9001', 'NVD', 'HIGH')
                """);
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (501, 'not-a-uuid', 'CVE-2024-9002', 'NVD', 'LOW')
                """);

            // Join rows:
            //   (1, 500) good
            //   (1, 500) dup → dedup
            //   (1, 501) malformed-UUID vuln → drop
            //   (3, 500) malformed-UUID svc → drop
            h.execute("INSERT INTO \"SERVICECOMPONENTS_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"SERVICECOMPONENT_ID\") VALUES (500, 1)");
            h.execute("INSERT INTO \"SERVICECOMPONENTS_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"SERVICECOMPONENT_ID\") VALUES (500, 1)");
            h.execute("INSERT INTO \"SERVICECOMPONENTS_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"SERVICECOMPONENT_ID\") VALUES (501, 1)");
            h.execute("INSERT INTO \"SERVICECOMPONENTS_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"SERVICECOMPONENT_ID\") VALUES (500, 3)");
        });

        runPipeline();

        // Malformed UUID probed.
        final List<Map<String, Object>> probe = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, bad_uuid
                      FROM "dt_v4_migration".probe_invalid_uuids
                     WHERE table_name = 'SERVICECOMPONENT'
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(probe).hasSize(1);
        assertThat(probe.get(0))
            .containsEntry("table_name", "SERVICECOMPONENT")
            .containsEntry("orig_id", 3L)
            .containsEntry("bad_uuid", "not-a-uuid");

        // Identity servicecomponent_canonical_id_map for valid-UUID rows.
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.servicecomponent_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id").containsExactly(
            tuple(1L, 1L),
            tuple(2L, 2L),
            tuple(4L, 4L)
        );

        // Full v5 SERVICECOMPONENT contents.
        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "UUID", "PROJECT_ID", "PARENT_SERVICECOMPONENT_ID",
                           "AUTHENTICATED", "X_TRUST_BOUNDARY", "LAST_RISKSCORE",
                           "DATA", "ENDPOINTS", "EXTERNAL_REFERENCES", "PROVIDER_ID"
                      FROM "SERVICECOMPONENT"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(3);

        // (1) parent: pass-through, native UUID, all four blobs preserved byte-for-byte.
        assertThat(rows.get(0))
            .containsEntry("name", "parent-svc")
            .containsEntry("uuid", UUID.fromString("00000000-0000-0000-0000-00000000aa01"))
            .containsEntry("project_id", 200L)
            .containsEntry("parent_servicecomponent_id", null)
            .containsEntry("authenticated", true)
            .containsEntry("x_trust_boundary", false);
        assertThat((byte[]) rows.get(0).get("data")).containsExactly(0x10, 0x11, 0x12);
        assertThat((byte[]) rows.get(0).get("endpoints")).containsExactly(0x20, 0x21, 0x22);
        assertThat((byte[]) rows.get(0).get("external_references")).containsExactly(0x30, 0x31, 0x32);
        assertThat((byte[]) rows.get(0).get("provider_id")).containsExactly(0x40, 0x41, 0x42);

        // (2) child: PROJECT_ID rewritten from loser (100) to winner (200);
        // PARENT_SERVICECOMPONENT_ID preserved (canonical).
        assertThat(rows.get(1))
            .containsEntry("name", "child-svc")
            .containsEntry("project_id", 200L)
            .containsEntry("parent_servicecomponent_id", 1L);

        // (4) Orphan: parent had malformed UUID → PARENT_SERVICECOMPONENT_ID NULL.
        assertThat(rows.get(2))
            .containsEntry("name", "svc-orphan")
            .containsEntry("parent_servicecomponent_id", null);

        // SERVICECOMPONENTS_VULNERABILITIES join: only (500, 1) survives.
        final List<Map<String, Object>> sv = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "VULNERABILITY_ID", "SERVICECOMPONENT_ID"
                      FROM "SERVICECOMPONENTS_VULNERABILITIES"
                     ORDER BY "VULNERABILITY_ID", "SERVICECOMPONENT_ID"
                    """).mapToMap().list());
        assertThat(sv).extracting("vulnerability_id", "servicecomponent_id")
            .containsExactly(tuple(500L, 1L));
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
