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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts POLICYVIOLATION migration: 3-column dedup on
 * {@code (COMPONENT_ID, PROJECT_ID, POLICYCONDITION_ID)} keeping the newest
 * {@code TIMESTAMP} per schema-changes §4.7, and native UUID conversion.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicyViolationIT {

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
    void migratesPolicyViolationKeepingNewestTimestamp() throws Exception {
        final UUID newerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "PROJECT_ID", "UUID")
                VALUES (10, 'lib', 1, '00000000-0000-0000-0000-00000000000a')
                """);
            h.execute("""
                INSERT INTO "POLICY" (
                    "ID", "INCLUDE_CHILDREN", "NAME", "ONLY_LATEST_PROJECT_VERSION",
                    "OPERATOR", "UUID", "VIOLATIONSTATE"
                )
                VALUES (50, TRUE, 'P1', FALSE, 'ALL',
                        'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'FAIL')
                """);
            h.execute("""
                INSERT INTO "POLICYCONDITION" (
                    "ID", "OPERATOR", "POLICY_ID", "SUBJECT", "UUID", "VALUE"
                )
                VALUES (500, 'MATCHES', 50, 'COORDINATES',
                        'cccccccc-cccc-cccc-cccc-cccccccccccc',
                        'pkg:maven/org.example/lib@1.0.0')
                """);

            h.execute("""
                INSERT INTO "POLICYVIOLATION" (
                    "ID", "COMPONENT_ID", "POLICYCONDITION_ID", "PROJECT_ID",
                    "TEXT", "TIMESTAMP", "TYPE", "UUID"
                )
                VALUES (1, 10, 500, 1, 'older', '2024-01-01T00:00:00Z', 'LICENSE',
                        '22222222-2222-2222-2222-222222222222')
                """);
            h.createUpdate("""
                INSERT INTO "POLICYVIOLATION" (
                    "ID", "COMPONENT_ID", "POLICYCONDITION_ID", "PROJECT_ID",
                    "TEXT", "TIMESTAMP", "TYPE", "UUID"
                )
                VALUES (2, 10, 500, 1, 'newer', '2024-06-01T00:00:00Z', 'LICENSE', :u)
                """).bind("u", newerUuid.toString()).execute();
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "COMPONENT_ID", "POLICYCONDITION_ID", "PROJECT_ID",
                           "TEXT", "TYPE", "UUID"
                      FROM "POLICYVIOLATION"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("id", 2L)
            .containsEntry("component_id", 10L)
            .containsEntry("policycondition_id", 500L)
            .containsEntry("project_id", 1L)
            .containsEntry("text", "newer")
            .containsEntry("type", "LICENSE")
            .containsEntry("uuid", newerUuid);
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
