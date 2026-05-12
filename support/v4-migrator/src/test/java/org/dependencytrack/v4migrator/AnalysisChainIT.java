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
 * Asserts the ANALYSIS / ANALYSISCOMMENT / VIOLATIONANALYSIS / VIOLATIONANALYSISCOMMENT
 * chain migrates 1:1 with v4 IDs preserved, FK references intact, and the additive v5
 * columns on ANALYSIS NULL-filled per schema-changes §8.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AnalysisChainIT {

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
    void migratesAnalysisChain() throws Exception {
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
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (100, '00000000-0000-0000-0000-000000000064', 'CVE-2024-0001', 'NVD', 'HIGH')
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
                VALUES (1000, 10, 500, 1, 'violated', '2024-06-01T00:00:00Z', 'LICENSE',
                        'dddddddd-dddd-dddd-dddd-dddddddddddd')
                """);

            h.execute("""
                INSERT INTO "ANALYSIS" (
                    "ID", "DETAILS", "JUSTIFICATION", "RESPONSE", "STATE",
                    "COMPONENT_ID", "PROJECT_ID", "SUPPRESSED", "VULNERABILITY_ID"
                )
                VALUES (700, 'details', 'CODE_NOT_REACHABLE', 'WILL_NOT_FIX', 'EXPLOITABLE',
                        10, 1, FALSE, 100)
                """);
            h.execute("""
                INSERT INTO "ANALYSISCOMMENT" (
                    "ID", "ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP"
                )
                VALUES (701, 700, 'looking into it', 'alice', '2024-06-02T00:00:00Z')
                """);

            h.execute("""
                INSERT INTO "VIOLATIONANALYSIS" (
                    "ID", "STATE", "COMPONENT_ID", "POLICYVIOLATION_ID", "PROJECT_ID", "SUPPRESSED"
                )
                VALUES (800, 'NOT_SET', 10, 1000, 1, FALSE)
                """);
            h.execute("""
                INSERT INTO "VIOLATIONANALYSISCOMMENT" (
                    "ID", "COMMENT", "COMMENTER", "TIMESTAMP", "VIOLATIONANALYSIS_ID"
                )
                VALUES (801, 'reviewing', 'bob', '2024-06-03T00:00:00Z', 800)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> analyses = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "DETAILS", "STATE", "COMPONENT_ID", "PROJECT_ID",
                           "VULNERABILITY_ID", "SUPPRESSED",
                           "CVSSV2VECTOR", "CVSSV2SCORE", "CVSSV3VECTOR", "CVSSV3SCORE",
                           "CVSSV4VECTOR", "CVSSV4SCORE", "OWASPVECTOR", "OWASPSCORE",
                           "SEVERITY", "VULNERABILITY_POLICY_ID"
                      FROM "ANALYSIS"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(analyses).hasSize(1);
        assertThat(analyses.get(0))
            .containsEntry("id", 700L)
            .containsEntry("details", "details")
            .containsEntry("state", "EXPLOITABLE")
            .containsEntry("component_id", 10L)
            .containsEntry("project_id", 1L)
            .containsEntry("vulnerability_id", 100L)
            .containsEntry("suppressed", false)
            .containsEntry("cvssv2vector", null)
            .containsEntry("cvssv2score", null)
            .containsEntry("cvssv3vector", null)
            .containsEntry("cvssv3score", null)
            .containsEntry("cvssv4vector", null)
            .containsEntry("cvssv4score", null)
            .containsEntry("owaspvector", null)
            .containsEntry("owaspscore", null)
            .containsEntry("severity", null)
            .containsEntry("vulnerability_policy_id", null);

        final List<Map<String, Object>> analysisComments = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "ANALYSIS_ID", "COMMENT", "COMMENTER"
                      FROM "ANALYSISCOMMENT"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(analysisComments).hasSize(1);
        assertThat(analysisComments.get(0))
            .containsEntry("id", 701L)
            .containsEntry("analysis_id", 700L)
            .containsEntry("comment", "looking into it")
            .containsEntry("commenter", "alice");

        final List<Map<String, Object>> violations = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "STATE", "COMPONENT_ID", "POLICYVIOLATION_ID", "PROJECT_ID", "SUPPRESSED"
                      FROM "VIOLATIONANALYSIS"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0))
            .containsEntry("id", 800L)
            .containsEntry("state", "NOT_SET")
            .containsEntry("component_id", 10L)
            .containsEntry("policyviolation_id", 1000L)
            .containsEntry("project_id", 1L)
            .containsEntry("suppressed", false);

        final List<Map<String, Object>> violationComments = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "COMMENT", "COMMENTER", "VIOLATIONANALYSIS_ID"
                      FROM "VIOLATIONANALYSISCOMMENT"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(violationComments).hasSize(1);
        assertThat(violationComments.get(0))
            .containsEntry("id", 801L)
            .containsEntry("comment", "reviewing")
            .containsEntry("commenter", "bob")
            .containsEntry("violationanalysis_id", 800L);
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
