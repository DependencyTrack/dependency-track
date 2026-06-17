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
 * v4 enforces UNIQUE(NAME) on TAG, so dedup is a no-op by construction. The migrator
 * still produces a {@code tag_canonical_id_map} for downstream join-table transforms to
 * consume; every orig_id maps to itself in the no-duplicates case.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TagDedupIT {

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
    void migratesTagsAndBuildsCanonicalMap() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (1, 'frontend')");
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (2, 'backend')");
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (5, 'security')");
        });

        runPipeline();

        final List<Map<String, Object>> tags = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"ID\", \"NAME\" FROM \"TAG\" ORDER BY \"ID\"").mapToMap().list());
        assertThat(tags).extracting("id", "name")
            .containsExactly(
                tuple(1L, "frontend"),
                tuple(2L, "backend"),
                tuple(5L, "security")
            );

        // Canonical map exists, has a row per source tag, and every orig_id maps to itself.
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM "dt_v4_migration".tag_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id")
            .containsExactly(
                tuple(1L, 1L),
                tuple(2L, 2L),
                tuple(5L, 5L)
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
