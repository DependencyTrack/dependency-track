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
 * Exercises {@code APIKEY}, {@code APIKEYS_TEAMS}, and {@code TEAMS_PERMISSIONS} together.
 * APIKEY is a straight 1:1; APIKEYS_TEAMS dedups via composite PK; TEAMS_PERMISSIONS rewrites
 * PERMISSION_ID through {@code permission_name_map}, silently dropping rows whose v4 NAME has
 * no v5 counterpart.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiKeyAdjunctsIT {

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
    void migratesApiKeysAndTeamJoins() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (1, 'VIEW_PORTFOLIO')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (2, 'SECRET_MANAGEMENT_READ')");
            h.execute("""
                INSERT INTO "APIKEY" ("ID", "COMMENT", "CREATED", "IS_LEGACY", "LAST_USED", "PUBLIC_ID", "SECRET_HASH")
                VALUES (10, 'first',  '2025-01-01T00:00:00Z', FALSE, '2025-02-01T00:00:00Z', 'abcdefgh', 'hash-one')
                """);
            h.execute("""
                INSERT INTO "APIKEY" ("ID", "COMMENT", "CREATED", "IS_LEGACY", "LAST_USED", "PUBLIC_ID", "SECRET_HASH")
                VALUES (11, 'second', '2025-01-02T00:00:00Z', TRUE,  NULL,                   'ijklmnop', 'hash-two')
                """);
            // Both keys mapped to team 1; the second row duplicates the first to assert
            // composite-PK dedup collapses them.
            h.execute("INSERT INTO \"APIKEYS_TEAMS\" (\"TEAM_ID\", \"APIKEY_ID\") VALUES (1, 10)");
            h.execute("INSERT INTO \"APIKEYS_TEAMS\" (\"TEAM_ID\", \"APIKEY_ID\") VALUES (1, 10)");
            h.execute("INSERT INTO \"APIKEYS_TEAMS\" (\"TEAM_ID\", \"APIKEY_ID\") VALUES (1, 11)");
            // Team has both v4 permissions; only VIEW_PORTFOLIO survives the name map.
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 1)");
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 2)");
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 1)");
        });

        runPipeline();

        final List<Map<String, Object>> apiKeys = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "COMMENT", "IS_LEGACY", "PUBLIC_ID", "SECRET_HASH"
                      FROM "APIKEY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(apiKeys).extracting("id", "comment", "is_legacy", "public_id", "secret_hash")
            .containsExactly(
                tuple(10L, "first",  false, "abcdefgh", "hash-one"),
                tuple(11L, "second", true,  "ijklmnop", "hash-two"));

        final List<Map<String, Object>> apiKeyTeams = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "TEAM_ID", "APIKEY_ID"
                      FROM "APIKEYS_TEAMS"
                     ORDER BY "TEAM_ID", "APIKEY_ID"
                    """).mapToMap().list());
        assertThat(apiKeyTeams).extracting("team_id", "apikey_id")
            .containsExactly(tuple(1L, 10L), tuple(1L, 11L));

        final List<Map<String, Object>> teamPerms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT t."NAME" AS team_name, p."NAME" AS permission_name
                      FROM "TEAMS_PERMISSIONS" tp
                      JOIN "TEAM" t       ON t."ID" = tp."TEAM_ID"
                      JOIN "PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
                     ORDER BY t."NAME", p."NAME"
                    """).mapToMap().list());
        assertThat(teamPerms).hasSize(1);
        assertThat(teamPerms.get(0))
            .containsEntry("team_name", "Engineering")
            .containsEntry("permission_name", "VIEW_PORTFOLIO");
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
