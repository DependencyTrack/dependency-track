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
 * Exercises the v4 PROJECT-keyed join-table transforms (POLICY_PROJECTS,
 * PROJECT_ACCESS_TEAMS, PROJECTS_TAGS). Two PROJECT rows under the same (NAME, VERSION)
 * collapse to the canonical winner (newest LAST_BOM_IMPORTED). Each join table is seeded
 * with rows referencing both the winner and the loser; ON CONFLICT DO NOTHING then
 * collapses the rewritten duplicates.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectJoinTablesIT {

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
    void rewritesProjectJoinTablesThroughCanonicalMap() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two PROJECTs collide on (NAME, VERSION). Canonical winner = ID 2 (newer LBI).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'Foo', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (2, 'Foo', '1.0', '00000000-0000-0000-0000-000000000002',
                        '2024-12-01T00:00:00Z')
                """);
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Eng', '00000000-0000-0000-0000-000000000011')");
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (1, 'frontend')");
            h.execute("""
                INSERT INTO "POLICY" (
                    "ID", "INCLUDE_CHILDREN", "NAME", "ONLY_LATEST_PROJECT_VERSION",
                    "OPERATOR", "UUID", "VIOLATIONSTATE"
                )
                VALUES (10, FALSE, 'P1', FALSE, 'ALL',
                        '00000000-0000-0000-0000-0000000000aa', 'FAIL')
                """);

            // Join rows referencing both the loser (1) and the winner (2).
            h.execute("INSERT INTO \"POLICY_PROJECTS\" (\"POLICY_ID\", \"PROJECT_ID\") VALUES (10, 1)");
            h.execute("INSERT INTO \"POLICY_PROJECTS\" (\"POLICY_ID\", \"PROJECT_ID\") VALUES (10, 2)");
            h.execute("INSERT INTO \"PROJECT_ACCESS_TEAMS\" (\"PROJECT_ID\", \"TEAM_ID\") VALUES (1, 1)");
            h.execute("INSERT INTO \"PROJECT_ACCESS_TEAMS\" (\"PROJECT_ID\", \"TEAM_ID\") VALUES (2, 1)");
            // NULL TEAM_ID must be dropped (v5 tightens to NOT NULL).
            h.execute("INSERT INTO \"PROJECT_ACCESS_TEAMS\" (\"PROJECT_ID\", \"TEAM_ID\") VALUES (2, NULL)");
            h.execute("INSERT INTO \"PROJECTS_TAGS\" (\"PROJECT_ID\", \"TAG_ID\") VALUES (1, 1)");
            h.execute("INSERT INTO \"PROJECTS_TAGS\" (\"PROJECT_ID\", \"TAG_ID\") VALUES (2, 1)");
        });

        runPipeline();

        final List<Map<String, Object>> policyProjects = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "POLICY_ID", "PROJECT_ID"
                      FROM "POLICY_PROJECTS"
                     ORDER BY "POLICY_ID", "PROJECT_ID"
                    """).mapToMap().list());
        assertThat(policyProjects).extracting("policy_id", "project_id")
            .containsExactly(tuple(10L, 2L));

        final List<Map<String, Object>> accessTeams = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "PROJECT_ID", "TEAM_ID"
                      FROM "PROJECT_ACCESS_TEAMS"
                     ORDER BY "PROJECT_ID", "TEAM_ID"
                    """).mapToMap().list());
        assertThat(accessTeams).extracting("project_id", "team_id")
            .containsExactly(tuple(2L, 1L));

        final List<Map<String, Object>> projectsTags = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "PROJECT_ID", "TAG_ID"
                      FROM "PROJECTS_TAGS"
                     ORDER BY "PROJECT_ID", "TAG_ID"
                    """).mapToMap().list());
        assertThat(projectsTags).extracting("project_id", "tag_id")
            .containsExactly(tuple(2L, 1L));
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
