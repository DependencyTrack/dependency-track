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
 * Three-deep PROJECT chain ({@code Root → Mid → Leaf}). Asserts the recursive closure
 * (incl. self-rows at depth 0) and the {@code ACTIVE} → {@code INACTIVE_SINCE} transform.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectHierarchyIT {

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
    void buildsClosureAndAppliesInactiveSinceTransform() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "PARENT_PROJECT_ID", "ACTIVE")
                VALUES (1, 'Root',  '1.0', '00000000-0000-0000-0000-000000000001', NULL, TRUE)
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "PARENT_PROJECT_ID", "ACTIVE")
                VALUES (2, 'Mid',   '1.0', '00000000-0000-0000-0000-000000000002', 1, TRUE)
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "PARENT_PROJECT_ID", "ACTIVE")
                VALUES (3, 'Leaf',  '1.0', '00000000-0000-0000-0000-000000000003', 2, FALSE)
                """);
        });

        runPipeline();

        // PROJECT: 3 rows, INACTIVE_SINCE only on Leaf (was ACTIVE=FALSE in v4).
        final List<Map<String, Object>> projects = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "PARENT_PROJECT_ID", "INACTIVE_SINCE"
                      FROM "PROJECT"
                     ORDER BY "ID"
                    """)
                .mapToMap()
                .list());
        assertThat(projects).hasSize(3);
        assertThat(projects.get(0)).containsEntry("name", "Root")
            .containsEntry("parent_project_id", null)
            .containsEntry("inactive_since", null);
        assertThat(projects.get(1)).containsEntry("name", "Mid")
            .containsEntry("parent_project_id", 1L)
            .containsEntry("inactive_since", null);
        // Leaf was inactive in v4 -> INACTIVE_SINCE = 'epoch'.
        assertThat(projects.get(2)).containsEntry("name", "Leaf")
            .containsEntry("parent_project_id", 2L);
        assertThat(projects.get(2).get("inactive_since")).isNotNull();

        // PROJECT_HIERARCHY closure:
        //   (1, 1, 0)  (2, 2, 0)  (3, 3, 0)   ← self-rows
        //   (1, 2, 1)  (2, 3, 1)              ← parent-child
        //   (1, 3, 2)                         ← grandparent-grandchild
        // Total: 6 rows.
        final List<Map<String, Object>> hierarchy = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH"
                      FROM "PROJECT_HIERARCHY"
                     ORDER BY "PARENT_PROJECT_ID", "DEPTH"
                    """)
                .mapToMap()
                .list());

        assertThat(hierarchy).hasSize(6);
        assertThat(hierarchy).extracting("parent_project_id", "child_project_id", "depth")
            .containsExactly(
                tuple(1L, 1L, 0),
                tuple(1L, 2L, 1),
                tuple(1L, 3L, 2),
                tuple(2L, 2L, 0),
                tuple(2L, 3L, 1),
                tuple(3L, 3L, 0)
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
