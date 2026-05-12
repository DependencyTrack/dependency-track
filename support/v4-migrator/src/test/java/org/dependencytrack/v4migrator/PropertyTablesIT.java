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
 * Asserts {@code CONFIGPROPERTY}, {@code PROJECT_PROPERTY}, {@code COMPONENT_PROPERTY}
 * migration per schema-changes §5.9 / §7.8 plus the v5.7.0 cleanup-delete replay:
 * ENCRYPTEDSTRING wipe, defectdojo.apiKey wipe (CONFIGPROPERTY only), drop rows whose
 * {@code PROPERTYTYPE} is outside the v5 enum, FK rewrites through canonical-id maps,
 * UUID conversion for COMPONENT_PROPERTY, and post-load Liquibase v5.7.0 DELETE replays.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PropertyTablesIT {

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
    void migratesPropertyTablesWithWipesAndCleanupReplay() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "UUID", "PROJECT_ID", "CLASSIFIER")
                VALUES (10, 'c', '00000000-0000-0000-0000-000000000010', 1, 'LIBRARY')
                """);

            // CONFIGPROPERTY rows.
            h.execute("""
                INSERT INTO "CONFIGPROPERTY" ("ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (1, 'general', 'maintenance.mode', 'BOOLEAN', 'false')
                """);
            h.execute("""
                INSERT INTO "CONFIGPROPERTY" ("ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (2, 'integrations', 'webhook.secret', 'ENCRYPTEDSTRING', 'cipher-text')
                """);
            h.execute("""
                INSERT INTO "CONFIGPROPERTY" ("ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (3, 'integrations', 'defectdojo.apiKey', 'STRING', 'plain-key')
                """);
            h.execute("""
                INSERT INTO "CONFIGPROPERTY" ("ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (4, 'general', 'opaque.blob', 'ENCRYPTED_BLOB', 'whatever')
                """);
            // Cleanup target: v5.7.0-22 deletes everything under GROUPNAME='search-indexes'.
            h.execute("""
                INSERT INTO "CONFIGPROPERTY" ("ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (5, 'search-indexes', 'enabled', 'BOOLEAN', 'true')
                """);

            // PROJECT_PROPERTY rows.
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (1, 'g', 1, 'k1', 'STRING', 'v')
                """);
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (2, 'g', 1, 'k2', 'ENCRYPTEDSTRING', 'cipher')
                """);
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (3, 'g', 1, 'k3', 'ENCRYPTED_BLOB', 'x')
                """);

            // COMPONENT_PROPERTY row (single happy path; pattern identical to PROJECT_PROPERTY).
            h.execute("""
                INSERT INTO "COMPONENT_PROPERTY"
                    ("ID", "COMPONENT_ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE", "UUID")
                VALUES (1, 10, 'g', 'k', 'STRING', 'v',
                        '00000000-0000-0000-0000-0000000000aa')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> cfg = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE"
                      FROM "CONFIGPROPERTY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        // (1) STRING preserved, (2) ENCRYPTEDSTRING wiped, (3) defectdojo wiped,
        // (4) unknown PROPERTYTYPE dropped, (5) search-indexes deleted by replay.
        assertThat(cfg).extracting("id", "groupname", "propertyname", "propertytype", "propertyvalue")
            .containsExactly(
                tuple(1L, "general", "maintenance.mode", "BOOLEAN", "false"),
                tuple(2L, "integrations", "webhook.secret", "STRING", null),
                tuple(3L, "integrations", "defectdojo.apiKey", "STRING", null)
            );

        final List<Map<String, Object>> pp = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE"
                      FROM "PROJECT_PROPERTY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(pp).extracting("id", "project_id", "propertyname", "propertytype", "propertyvalue")
            .containsExactly(
                tuple(1L, 1L, "k1", "STRING", "v"),
                tuple(2L, 1L, "k2", "STRING", null)
            );

        final List<Map<String, Object>> cp = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "COMPONENT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE", "UUID"
                      FROM "COMPONENT_PROPERTY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(cp).hasSize(1);
        assertThat(cp.get(0))
            .containsEntry("id", 1L)
            .containsEntry("component_id", 10L)
            .containsEntry("propertyname", "k")
            .containsEntry("propertytype", "STRING")
            .containsEntry("propertyvalue", "v")
            .containsEntry("uuid", UUID.fromString("00000000-0000-0000-0000-0000000000aa"));
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
