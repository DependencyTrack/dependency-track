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
 * Asserts PROJECTMETRICS migration: drops v4-only {@code COLLECTION_LOGIC} and
 * {@code COLLECTION_LOGIC_CHANGED} columns per schema-changes §7.4 and refreshes
 * {@code PORTFOLIOMETRICS_GLOBAL} as a smoke check.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProjectMetricsIT {

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
    void migratesProjectMetricsAndDropsCollectionLogicColumns() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);
            h.execute("""
                INSERT INTO "PROJECTMETRICS" (
                    "ID", "PROJECT_ID", "COLLECTION_LOGIC", "COLLECTION_LOGIC_CHANGED",
                    "COMPONENTS", "CRITICAL", "HIGH", "LOW", "MEDIUM",
                    "FIRST_OCCURRENCE", "LAST_OCCURRENCE",
                    "RISKSCORE", "SUPPRESSED", "VULNERABILITIES", "VULNERABLECOMPONENTS"
                ) VALUES (
                    1, 1, 'AGGREGATE_DIRECT_CHILDREN', TRUE,
                    3, 1, 2, 0, 0,
                    NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day',
                    7.5, 0, 3, 2
                )
                """);
        });

        runPipeline();

        // The COLLECTION_LOGIC* columns must not be present on v5 PROJECTMETRICS.
        final List<String> columns = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT column_name
                      FROM information_schema.columns
                     WHERE table_name = 'PROJECTMETRICS'
                       AND table_schema = current_schema()
                    """).mapTo(String.class).list());
        assertThat(columns).doesNotContain("COLLECTION_LOGIC", "COLLECTION_LOGIC_CHANGED");

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "PROJECT_ID", "COMPONENTS", "VULNERABILITIES", "VULNERABLECOMPONENTS"
                      FROM "PROJECTMETRICS"
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("project_id", 1L)
            .containsEntry("components", 3)
            .containsEntry("vulnerabilities", 3)
            .containsEntry("vulnerablecomponents", 2);

        // Smoke: the post-load REFRESH MATERIALIZED VIEW completed; the view is queryable.
        final Long viewRows = target.jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"PORTFOLIOMETRICS_GLOBAL\"").mapTo(Long.class).one());
        assertThat(viewRows).isNotNull();
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
