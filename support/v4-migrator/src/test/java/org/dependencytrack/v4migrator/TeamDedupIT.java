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
 * Two v4 TEAMs share a NAME. The migrator collapses to MIN(ID), the v5 UNIQUE constraint
 * on TEAM.NAME holds, and TEAM_ID references in USERS_TEAMS are rewritten to the canonical ID.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TeamDedupIT {

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
    void collapsesDuplicateTeamsByName() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two TEAMs share NAME 'Engineering'; canonical = ID 1 (MIN(ID)).
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (5, 'Engineering', '55555555-5555-5555-5555-555555555555')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (7, 'Security',    '77777777-7777-7777-7777-777777777777')");

            // Two managed users; one belongs to canonical TEAM 1, the other to the
            // non-canonical TEAM 5 (which must be rewired to 1).
            h.execute("""
                INSERT INTO "MANAGEDUSER" (
                    "ID", "USERNAME", "PASSWORD", "FORCE_PASSWORD_CHANGE",
                    "LAST_PASSWORD_CHANGE", "NON_EXPIRY_PASSWORD", "SUSPENDED"
                )
                VALUES (10, 'alice', 'h', FALSE, '2025-01-01T00:00:00Z', FALSE, FALSE)
                """);
            h.execute("""
                INSERT INTO "MANAGEDUSER" (
                    "ID", "USERNAME", "PASSWORD", "FORCE_PASSWORD_CHANGE",
                    "LAST_PASSWORD_CHANGE", "NON_EXPIRY_PASSWORD", "SUSPENDED"
                )
                VALUES (11, 'bob', 'h', FALSE, '2025-01-01T00:00:00Z', FALSE, FALSE)
                """);
            h.execute("INSERT INTO \"MANAGEDUSERS_TEAMS\" (\"TEAM_ID\", \"MANAGEDUSER_ID\") VALUES (1, 10)");
            h.execute("INSERT INTO \"MANAGEDUSERS_TEAMS\" (\"TEAM_ID\", \"MANAGEDUSER_ID\") VALUES (5, 11)");
            h.execute("INSERT INTO \"MANAGEDUSERS_TEAMS\" (\"TEAM_ID\", \"MANAGEDUSER_ID\") VALUES (7, 11)");
        });

        runPipeline();

        // v5 TEAM: canonical IDs only (1, 7).
        final List<Map<String, Object>> teams = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"ID\", \"NAME\" FROM \"TEAM\" ORDER BY \"ID\"").mapToMap().list());
        assertThat(teams).extracting("id", "name")
            .containsExactly(tuple(1L, "Engineering"), tuple(7L, "Security"));

        // USERS_TEAMS: alice → 1, bob → 1 (rewired from 5), bob → 7. ON CONFLICT DO NOTHING
        // collapses any redundant (USER_ID, TEAM_ID) pairs.
        final List<Map<String, Object>> userTeams = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT u."USERNAME", ut."TEAM_ID"
                      FROM "USERS_TEAMS" ut
                      JOIN "USER" u ON u."ID" = ut."USER_ID"
                     ORDER BY u."USERNAME", ut."TEAM_ID"
                    """).mapToMap().list());
        assertThat(userTeams).extracting("username", "team_id")
            .containsExactly(
                tuple("alice", 1L),
                tuple("bob",   1L),
                tuple("bob",   7L)
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
