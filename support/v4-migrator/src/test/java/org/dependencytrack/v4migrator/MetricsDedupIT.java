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

/**
 * Asserts DEPENDENCYMETRICS composite-key dedup on
 * {@code (COMPONENT_ID, LAST_OCCURRENCE)} keeping {@code MAX(ID)}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MetricsDedupIT {

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
    void keepsRowWithHighestIdForCompositeKey() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "PROJECT_ID", "UUID")
                VALUES (10, 'lib', 1, '00000000-0000-0000-0000-00000000000a')
                """);
            // Two rows for the same (COMPONENT_ID, LAST_OCCURRENCE); keep MAX(ID).
            h.execute("""
                INSERT INTO "DEPENDENCYMETRICS" (
                    "ID", "COMPONENT_ID", "PROJECT_ID",
                    "CRITICAL", "HIGH", "LOW", "MEDIUM",
                    "FIRST_OCCURRENCE", "LAST_OCCURRENCE",
                    "RISKSCORE", "SUPPRESSED", "VULNERABILITIES"
                ) VALUES
                  (1, 10, 1, 1, 0, 0, 0, '2026-05-12T10:00:00Z', '2026-05-12T10:00:00Z', 1.5, 0, 1),
                  (2, 10, 1, 7, 0, 0, 0, '2026-05-12T10:00:00Z', '2026-05-12T10:00:00Z', 9.9, 0, 7)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "COMPONENT_ID", "CRITICAL", "VULNERABILITIES"
                      FROM "DEPENDENCYMETRICS"
                     WHERE "COMPONENT_ID" = 10
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("component_id", 10L)
            .containsEntry("critical", 7)
            .containsEntry("vulnerabilities", 7);
    }

    private void runPipeline() throws Exception {
        final GlobalOptions global = new GlobalOptions();
        global.targetUrl = target.jdbcUrl();
        global.targetUser = target.username();
        global.targetPass = target.password();
        global.stagingSchema = "dt_v4_migration";
        global.logLevel = "INFO";
        // Retention defaults via --metrics-retention-days = -1 → fallback to 90 days.
        // The seed rows are dated yesterday; 90 days easily covers them. A large retention
        // would balloon partition pre-creation.

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = source.jdbcUrl();
        src.sourceUser = source.username();
        src.sourcePass = source.password();

        new ExtractPhase(global, src, target.jdbi(), 90).run();
        new TransformPhase(global, target.jdbi()).run();
        new LoadPhase(global, target.jdbi(), false).run();
    }
}
