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
 * Exercises the derived PROJECT_ACCESS_USERS transform (pipeline §7.5). Asserts the
 * trigger-blocked v5 table is populated transitively from PROJECT_ACCESS_TEAMS and
 * USERS_TEAMS, and that the load phase brackets the insert with the trigger disable.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectAccessUsersIT {

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
    void backfillsUserAccessViaTeamMembership() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);
            h.execute("""
                INSERT INTO "TEAM" ("ID", "NAME", "UUID")
                VALUES (10, 'Eng', '00000000-0000-0000-0000-00000000000a')
                """);
            h.execute("""
                INSERT INTO "MANAGEDUSER" (
                    "ID", "USERNAME", "PASSWORD", "FULLNAME", "EMAIL",
                    "FORCE_PASSWORD_CHANGE", "LAST_PASSWORD_CHANGE",
                    "NON_EXPIRY_PASSWORD", "SUSPENDED"
                )
                VALUES (100, 'alice', 'hash', 'Alice', 'alice@example.com',
                        FALSE, '2025-01-01T00:00:00Z', FALSE, FALSE)
                """);
            h.execute("""
                INSERT INTO "MANAGEDUSERS_TEAMS" ("TEAM_ID", "MANAGEDUSER_ID")
                VALUES (10, 100)
                """);
            h.execute("""
                INSERT INTO "PROJECT_ACCESS_TEAMS" ("PROJECT_ID", "TEAM_ID")
                VALUES (1, 10)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT pau."PROJECT_ID", u."USERNAME"
                      FROM "PROJECT_ACCESS_USERS" pau
                      JOIN "USER" u ON u."ID" = pau."USER_ID"
                     ORDER BY pau."PROJECT_ID", u."USERNAME"
                    """).mapToMap().list());

        assertThat(rows).extracting("project_id", "username")
            .containsExactly(tuple(1L, "alice"));
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
