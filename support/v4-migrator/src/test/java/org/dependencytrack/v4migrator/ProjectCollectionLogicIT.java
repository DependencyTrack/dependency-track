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
 * Asserts that {@code PROJECT.COLLECTION_LOGIC} and {@code COLLECTION_TAG_ID} are
 * reconciled to satisfy the v5 {@code PROJECT_COLLECTION_TAG_REQUIRED_check} constraint.
 * v4 has no constraint tying the two columns together, so a v4 instance can hold
 * {@code AGGREGATE_DIRECT_CHILDREN_WITH_TAG} without a tag, or a collection tag alongside
 * a logic that does not use one.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectCollectionLogicIT {

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
    void reconcilesCollectionLogicAndTagForV5Constraint() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (1, 'frontend')");

            // Incomplete collection project: WITH_TAG logic but no tag. v4 permits this.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "COLLECTION_LOGIC", "COLLECTION_TAG")
                VALUES (1, 'NoTag', '1.0', '00000000-0000-0000-0000-000000000001',
                        'AGGREGATE_DIRECT_CHILDREN_WITH_TAG', NULL)
                """);

            // Tag set alongside a logic that does not use one. Also rejected by v5.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "COLLECTION_LOGIC", "COLLECTION_TAG")
                VALUES (2, 'StrayTag', '1.0', '00000000-0000-0000-0000-000000000002',
                        'AGGREGATE_DIRECT_CHILDREN', 1)
                """);

            // Well-formed collection project: preserved as-is.
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "COLLECTION_LOGIC", "COLLECTION_TAG")
                VALUES (3, 'Valid', '1.0', '00000000-0000-0000-0000-000000000003',
                        'AGGREGATE_DIRECT_CHILDREN_WITH_TAG', 1)
                """);
        });

        runPipeline();

        final Long tagId = target.jdbi()
                .withHandle(h -> h.createQuery("SELECT \"ID\" FROM \"TAG\" WHERE \"NAME\" = 'frontend'")
                        .mapTo(Long.class)
                        .one());

        final List<Map<String, Object>> projects =
                target.jdbi().withHandle(h -> h.createQuery("""
                SELECT "ID", "COLLECTION_LOGIC", "COLLECTION_TAG_ID"
                  FROM "PROJECT"
                 ORDER BY "ID"
                """).mapToMap().list());
        assertThat(projects)
                .extracting("id", "collection_logic", "collection_tag_id")
                .containsExactly(
                        // Logic dropped: without a tag it cannot aggregate anything.
                        tuple(1L, null, null),
                        // Tag dropped: this logic does not use one.
                        tuple(2L, "AGGREGATE_DIRECT_CHILDREN", null),
                        tuple(3L, "AGGREGATE_DIRECT_CHILDREN_WITH_TAG", tagId));
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
