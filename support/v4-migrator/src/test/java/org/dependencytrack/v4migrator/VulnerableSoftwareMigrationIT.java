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
 * Asserts VULNERABLESOFTWARE migration: PART/VENDOR/PRODUCT lowercased (§5.7), UUID
 * conversion + probe (§6.1), PURL pass-through (§6.7), identity canonical map.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VulnerableSoftwareMigrationIT {

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
    void lowercasesPartVendorProductAndProbesMalformedUuid() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (10, '00000000-0000-0000-0000-00000000000a', 'CVE-2024-0010', 'NVD', 'HIGH')
                """);
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" (
                    "ID", "UUID", "PART", "VENDOR", "PRODUCT", "VERSION",
                    "PURL", "CPE23", "VULNERABLE"
                )
                VALUES (
                    1, '00000000-0000-0000-0000-000000000001',
                    'Application', 'Foo', 'Bar', '1.2.3',
                    'pkg:maven/foo/bar@1.2.3',
                    'cpe:2.3:a:foo:bar:1.2.3:*:*:*:*:*:*:*',
                    true
                )
                """);
            // Junction reference required: orphan VS rows are dropped per spec.
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                VALUES (10, 1)
                """);

            // Malformed UUID: probed and excluded.
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" ("ID", "UUID", "PART", "VULNERABLE")
                VALUES (2, 'not-a-uuid', 'a', false)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> probe = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, bad_uuid
                      FROM "dt_v4_migration".probe_invalid_uuids
                     WHERE table_name = 'VULNERABLESOFTWARE'
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(probe).hasSize(1);
        assertThat(probe.get(0))
            .containsEntry("orig_id", 2L)
            .containsEntry("bad_uuid", "not-a-uuid");

        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM dt_v4_migration.vulnerablesoftware_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id").containsExactly(tuple(1L, 1L));

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "UUID", "PART", "VENDOR", "PRODUCT", "VERSION", "PURL",
                           "CPE23", "VULNERABLE"
                      FROM "VULNERABLESOFTWARE"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("id", 1L)
            .containsEntry("uuid", UUID.fromString("00000000-0000-0000-0000-000000000001"))
            .containsEntry("part", "application")
            .containsEntry("vendor", "foo")
            .containsEntry("product", "bar")
            .containsEntry("version", "1.2.3")
            .containsEntry("purl", "pkg:maven/foo/bar@1.2.3")
            .containsEntry("cpe23", "cpe:2.3:a:foo:bar:1.2.3:*:*:*:*:*:*:*")
            .containsEntry("vulnerable", true);
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
