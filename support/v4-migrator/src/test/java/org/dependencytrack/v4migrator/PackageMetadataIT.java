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
 * Exercises the derived PACKAGE_METADATA transform per Liquibase changeset v5.7.0-52.
 * Asserts NAME/NAMESPACE/repository-type join semantics and the PURL forbidden-char filter.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PackageMetadataIT {

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
    void buildsPackageMetadataAndSkipsForbiddenPurls() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001')
                """);

            // Good Maven component: PURLCOORDINATES -> 'pkg:maven/com.example/foo' after @-split.
            h.execute("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "GROUP", "UUID", "PROJECT_ID", "PURL", "PURLCOORDINATES"
                )
                VALUES (
                    1, 'foo', 'com.example',
                    '00000000-0000-0000-0000-000000000010', 1,
                    'pkg:maven/com.example/foo@1.0.0',
                    'pkg:maven/com.example/foo@1.0.0'
                )
                """);

            // Component whose post-@-strip PURL still contains a forbidden char (#fragment
            // appears before the @, so split_part doesn't remove it). Must be filtered out.
            h.execute("""
                INSERT INTO "COMPONENT" (
                    "ID", "NAME", "GROUP", "UUID", "PROJECT_ID", "PURL", "PURLCOORDINATES"
                )
                VALUES (
                    2, 'bad', 'test',
                    '00000000-0000-0000-0000-000000000020', 1,
                    'pkg:maven/test/bad#frag@1.0',
                    'pkg:maven/test/bad#frag@1.0'
                )
                """);

            // REPOSITORY_META_COMPONENT for the good Maven component.
            // Note: v4 schema enforces uniqueness on (TYPE, NAMESPACE, NAME), so the dedup
            // arm of DISTINCT ON (PURL) is unreachable with real source data.
            h.execute("""
                INSERT INTO "REPOSITORY_META_COMPONENT" (
                    "ID", "LAST_CHECK", "LATEST_VERSION", "NAME", "NAMESPACE", "REPOSITORY_TYPE"
                )
                VALUES (2, '2024-12-01T00:00:00Z', '1.3.0', 'foo', 'com.example', 'MAVEN')
                """);
            // Matches the bad component; filtered out by forbidden-char check.
            h.execute("""
                INSERT INTO "REPOSITORY_META_COMPONENT" (
                    "ID", "LAST_CHECK", "LATEST_VERSION", "NAME", "NAMESPACE", "REPOSITORY_TYPE"
                )
                VALUES (3, '2024-06-01T00:00:00Z', '2.0.0', 'bad', 'test', 'MAVEN')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "PURL", "LATEST_VERSION", "RESOLVED_AT",
                           "RESOLVED_BY", "RESOLVED_FROM", "LATEST_VERSION_PUBLISHED_AT"
                      FROM "PACKAGE_METADATA"
                     ORDER BY "PURL"
                    """).mapToMap().list());

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
            .containsEntry("purl", "pkg:maven/com.example/foo")
            .containsEntry("latest_version", "1.3.0")
            .containsEntry("resolved_by", null)
            .containsEntry("resolved_from", null)
            .containsEntry("latest_version_published_at", null);
        assertThat(rows.get(0).get("resolved_at")).isNotNull();
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
