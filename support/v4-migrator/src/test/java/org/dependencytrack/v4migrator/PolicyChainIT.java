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
import static org.assertj.core.api.Assertions.tuple;

/**
 * Exercises the v4 POLICY / POLICYCONDITION / POLICY_TAGS migrations: native uuid conversion,
 * pass-through of VALUE (widened to text), NULL-fill of the new VIOLATIONTYPE column, and
 * TAG_ID rewrite through {@code tag_canonical_id_map}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicyChainIT {

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
    void migratesPolicyChain() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (1, 'frontend')");
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (2, 'backend')");
            h.execute("""
                INSERT INTO "POLICY" (
                    "ID", "INCLUDE_CHILDREN", "NAME", "ONLY_LATEST_PROJECT_VERSION",
                    "OPERATOR", "UUID", "VIOLATIONSTATE"
                )
                VALUES (10, TRUE, 'Strict', FALSE,
                        'ALL',
                        'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                        'FAIL')
                """);
            h.execute("""
                INSERT INTO "POLICYCONDITION" (
                    "ID", "OPERATOR", "POLICY_ID", "SUBJECT", "UUID", "VALUE"
                )
                VALUES (100, 'MATCHES', 10, 'COORDINATES',
                        'cccccccc-cccc-cccc-cccc-cccccccccccc',
                        'pkg:maven/org.example/lib@1.0.0')
                """);
            h.execute("INSERT INTO \"POLICY_TAGS\" (\"POLICY_ID\", \"TAG_ID\") VALUES (10, 1)");
            h.execute("INSERT INTO \"POLICY_TAGS\" (\"POLICY_ID\", \"TAG_ID\") VALUES (10, 2)");
        });

        runPipeline();

        final List<Map<String, Object>> policies = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "OPERATOR", "VIOLATIONSTATE",
                           "INCLUDE_CHILDREN", "ONLY_LATEST_PROJECT_VERSION", "UUID"
                      FROM "POLICY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(policies).hasSize(1);
        assertThat(policies.get(0))
            .containsEntry("id", 10L)
            .containsEntry("name", "Strict")
            .containsEntry("operator", "ALL")
            .containsEntry("violationstate", "FAIL")
            .containsEntry("include_children", true)
            .containsEntry("only_latest_project_version", false)
            .containsEntry("uuid", UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));

        final List<Map<String, Object>> conditions = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "OPERATOR", "POLICY_ID", "SUBJECT", "UUID", "VALUE", "VIOLATIONTYPE"
                      FROM "POLICYCONDITION"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(conditions).hasSize(1);
        assertThat(conditions.get(0))
            .containsEntry("id", 100L)
            .containsEntry("operator", "MATCHES")
            .containsEntry("policy_id", 10L)
            .containsEntry("subject", "COORDINATES")
            .containsEntry("uuid", UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc"))
            .containsEntry("value", "pkg:maven/org.example/lib@1.0.0")
            .containsEntry("violationtype", null);

        final List<Map<String, Object>> joins = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "POLICY_ID", "TAG_ID"
                      FROM "POLICY_TAGS"
                     ORDER BY "TAG_ID"
                    """).mapToMap().list());
        assertThat(joins).extracting("policy_id", "tag_id")
            .containsExactly(
                tuple(10L, 1L),
                tuple(10L, 2L)
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
