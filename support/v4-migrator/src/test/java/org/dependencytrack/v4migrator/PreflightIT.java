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
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.preflight.Preflight.Mode;
import org.dependencytrack.v4migrator.preflight.PreflightResult;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PreflightIT {

    private V5TargetContainer target;

    @BeforeAll
    void start() {
        target = new V5TargetContainer().start();
    }

    @AfterAll
    void stop() {
        if (target != null) {
            target.close();
        }
    }

    @Test
    void preflightPassesOnFreshV5() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = target.jdbcUrl();
        opts.targetUser = target.username();
        opts.targetPass = target.password();
        opts.stagingSchema = "dt_v4_migration";
        opts.logLevel = "INFO";

        final PreflightResult result = new Preflight(target.jdbi(), null, opts).run();
        assertThat(result.ok())
            .as("preflight should pass on a fresh v5 schema; failures: %s", result.failures())
            .isTrue();
    }

    @Test
    void preflightFailsWhenSourceUnreachable() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = target.jdbcUrl();
        opts.targetUser = target.username();
        opts.targetPass = target.password();
        opts.stagingSchema = "dt_v4_migration_src_unreachable";
        opts.logLevel = "INFO";

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = "jdbc:postgresql://127.0.0.1:1/nope";
        src.sourceUser = "x";
        src.sourcePass = "x";

        final PreflightResult result = new Preflight(target.jdbi(), src, opts).run();
        assertThat(result.ok()).isFalse();
        assertThat(result.failures()).anyMatch(f -> f.startsWith("Could not connect to source database:"));
    }

    @Test
    void preflightConnectsToSourceWithV4Marker() {
        // Reuse the v5 target container as a stand-in source: it has a public."PROJECT" table,
        // so the v4 marker check passes. The point of the test is to prove preflight actually
        // opens the connection and runs the marker query.
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = target.jdbcUrl();
        opts.targetUser = target.username();
        opts.targetPass = target.password();
        opts.stagingSchema = "dt_v4_migration_src_ok";
        opts.logLevel = "INFO";

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = target.jdbcUrl();
        src.sourceUser = target.username();
        src.sourcePass = target.password();

        final PreflightResult result = new Preflight(target.jdbi(), src, opts).run();
        assertThat(result.ok())
            .as("preflight should pass with reachable source; failures: %s", result.failures())
            .isTrue();
    }

    @Test
    void shouldFindV4MarkerInExplicitSourceSchema() {
        // Create a PROJECT table in a non-default schema of the v5 target (used as stand-in
        // source). With --source-schema pointing at it, the marker query must find it.
        target.jdbi().useHandle(h -> {
            h.execute("CREATE SCHEMA IF NOT EXISTS alt_v4");
            h.execute("CREATE TABLE IF NOT EXISTS alt_v4.\"PROJECT\" (\"ID\" bigint)");
        });
        try {
            final GlobalOptions opts = new GlobalOptions();
            opts.targetUrl = target.jdbcUrl();
            opts.targetUser = target.username();
            opts.targetPass = target.password();
            opts.stagingSchema = "dt_v4_migration_alt_schema";
            opts.logLevel = "INFO";

            final SourceOptions src = new SourceOptions();
            src.sourceUrl = target.jdbcUrl();
            src.sourceUser = target.username();
            src.sourcePass = target.password();
            src.sourceSchema = "alt_v4";

            final PreflightResult result = new Preflight(target.jdbi(), src, opts).run();
            assertThat(result.ok())
                .as("preflight should find PROJECT under alt_v4; failures: %s", result.failures())
                .isTrue();
        } finally {
            target.jdbi().useHandle(h -> h.execute("DROP SCHEMA alt_v4 CASCADE"));
        }
    }

    @Test
    void shouldFailMarkerWhenSourceSchemaHasNoV4Tables() {
        // Empty schema → marker must miss → preflight fails with the expected message.
        target.jdbi().useHandle(h -> h.execute("CREATE SCHEMA IF NOT EXISTS empty_v4"));
        try {
            final GlobalOptions opts = new GlobalOptions();
            opts.targetUrl = target.jdbcUrl();
            opts.targetUser = target.username();
            opts.targetPass = target.password();
            opts.stagingSchema = "dt_v4_migration_empty_schema";
            opts.logLevel = "INFO";

            final SourceOptions src = new SourceOptions();
            src.sourceUrl = target.jdbcUrl();
            src.sourceUser = target.username();
            src.sourcePass = target.password();
            src.sourceSchema = "empty_v4";

            final PreflightResult result = new Preflight(target.jdbi(), src, opts).run();
            assertThat(result.ok()).isFalse();
            assertThat(result.failures())
                .anyMatch(f -> f.contains("does not contain expected v4 table PROJECT"));
        } finally {
            target.jdbi().useHandle(h -> h.execute("DROP SCHEMA empty_v4 CASCADE"));
        }
    }

    @Test
    void preflightRejectsPopulatedV5() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = target.jdbcUrl();
        opts.targetUser = target.username();
        opts.targetPass = target.password();
        opts.stagingSchema = "dt_v4_migration_populated";
        opts.logLevel = "INFO";

        target.jdbi().useHandle(h -> h.execute(
            "INSERT INTO \"PROJECT\" (\"NAME\", \"UUID\") VALUES ('test', gen_random_uuid())"));
        try {
            final PreflightResult result = new Preflight(target.jdbi(), null, opts).run();
            assertThat(result.ok()).isFalse();
            assertThat(result.failures()).anyMatch(f -> f.contains("PROJECT") && f.contains("not empty"));
            assertThat(result.exitCode()).isEqualTo(ExitCode.PREFLIGHT_FAILED);
        } finally {
            target.jdbi().useHandle(h -> h.execute("TRUNCATE \"PROJECT\" CASCADE"));
        }
    }

    @Test
    void shouldAcceptPopulatedV5InPostLoadMode() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = target.jdbcUrl();
        opts.targetUser = target.username();
        opts.targetPass = target.password();
        opts.stagingSchema = "dt_v4_migration_post_load";
        opts.logLevel = "INFO";

        target.jdbi().useHandle(h -> h.execute(
            "INSERT INTO \"PROJECT\" (\"NAME\", \"UUID\") VALUES ('test', gen_random_uuid())"));
        try {
            final PreflightResult result = new Preflight(target.jdbi(), null, opts, Mode.POST_LOAD).run();
            assertThat(result.ok())
                .as("POST_LOAD preflight must tolerate populated v5 tables; failures: %s", result.failures())
                .isTrue();
        } finally {
            target.jdbi().useHandle(h -> h.execute("TRUNCATE \"PROJECT\" CASCADE"));
        }
    }
}
