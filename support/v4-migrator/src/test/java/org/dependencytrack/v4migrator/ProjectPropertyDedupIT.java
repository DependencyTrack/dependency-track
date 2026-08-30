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
 * Asserts that {@code PROJECT_PROPERTY} rows surviving the §4.8 PROJECT collapse are
 * deduplicated on the v5 natural key ({@code PROJECT_ID}, {@code GROUPNAME},
 * {@code PROPERTYNAME}). Two projects that are distinct in v4 can rewrite onto the same
 * canonical {@code PROJECT_ID}, turning two valid v4 rows into one duplicate key.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectPropertyDedupIT {

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
    void dedupesProjectPropertiesOfCollapsedProjects() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two rows under ("Foo", "1.0"); canonical winner = ID 2 (newest LAST_BOM_IMPORTED).
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'Foo', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (2, 'Foo', '1.0', '00000000-0000-0000-0000-000000000002',
                        '2024-06-01T00:00:00Z')
                """);

            // Same (GROUPNAME, PROPERTYNAME) on both projects. Distinct in v4 because the
            // PROJECT_IDs differ; identical once both rewrite onto canonical PROJECT_ID 2.
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (10, 'bifrost', 1, 'component-deployType', 'STRING', 'from-loser')
                """);
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (11, 'bifrost', 2, 'component-deployType', 'STRING', 'from-winner')
                """);

            // A property that is unique after the rewrite must be preserved.
            h.execute("""
                INSERT INTO "PROJECT_PROPERTY"
                    ("ID", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES (12, 'bifrost', 1, 'other-key', 'STRING', 'kept')
                """);
        });

        runPipeline();

        // MIN(ID) wins, matching the canonical-ID convention used by MAPPEDLDAPGROUP.
        final List<Map<String, Object>> properties =
                target.jdbi().withHandle(h -> h.createQuery("""
                SELECT "ID", "PROJECT_ID", "GROUPNAME", "PROPERTYNAME", "PROPERTYVALUE"
                  FROM "PROJECT_PROPERTY"
                 ORDER BY "ID"
                """).mapToMap().list());
        assertThat(properties)
                .extracting("id", "project_id", "groupname", "propertyname", "propertyvalue")
                .containsExactly(
                        tuple(10L, 2L, "bifrost", "component-deployType", "from-loser"),
                        tuple(12L, 2L, "bifrost", "other-key", "kept"));
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
