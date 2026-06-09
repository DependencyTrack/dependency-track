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
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.preflight.Preflight.Mode;
import org.dependencytrack.v4migrator.preflight.PreflightResult;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the {@code bootstrap} subcommand and the {@link Mode#PRE_BOOTSTRAP} preflight mode.
 * Uses a plain {@link PostgreSQLContainer} (no Flyway pre-applied) to exercise the cold-start
 * code path.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BootstrapIT {

    private static final DockerImageName IMAGE = DockerImageName.parse("postgres:14-alpine");

    private PostgreSQLContainer<?> container;

    @BeforeAll
    void start() {
        container = new PostgreSQLContainer<>(IMAGE)
            .withDatabaseName("dtrackv5")
            .withUsername("dt")
            .withPassword("dt");
        container.start();
    }

    @AfterAll
    void stop() {
        if (container != null) {
            container.stop();
        }
    }

    @Test
    @Order(1)
    void preBootstrapPreflightSkipsSchemaChecksOnFreshDb() {
        final GlobalOptions opts = optsForContainer();
        final PreflightResult result = new Preflight(jdbi(), null, opts, Mode.PRE_BOOTSTRAP).run();
        assertThat(result.ok())
            .as("pre-bootstrap preflight should pass on a database without v5 schema; failures: %s",
                result.failures())
            .isTrue();
    }

    @Test
    @Order(2)
    void shouldRejectPreBootstrapWhenV4SchemaMarkersPresent() {
        jdbi().useHandle(h -> {
            h.execute("CREATE TABLE \"SCHEMAVERSION\" (id int)");
            h.execute("CREATE TABLE \"EVENTSERVICELOG\" (id int)");
        });
        try {
            final GlobalOptions opts = optsForContainer();
            final PreflightResult result = new Preflight(jdbi(), null, opts, Mode.PRE_BOOTSTRAP).run();
            assertThat(result.ok()).isFalse();
            assertThat(result.failures())
                .anyMatch(f -> f.contains("v4 Dependency-Track database")
                    && f.contains("SCHEMAVERSION")
                    && f.contains("EVENTSERVICELOG"));
        } finally {
            jdbi().useHandle(h -> {
                h.execute("DROP TABLE \"SCHEMAVERSION\"");
                h.execute("DROP TABLE \"EVENTSERVICELOG\"");
            });
        }
    }

    @Test
    @Order(3)
    void defaultPreflightRejectsFreshDbWithActionableMessage() {
        final GlobalOptions opts = optsForContainer();
        opts.stagingSchema = "dt_v4_migration_default_check";
        final PreflightResult result = new Preflight(jdbi(), null, opts, Mode.DEFAULT).run();
        assertThat(result.ok()).isFalse();
        assertThat(result.failures()).anyMatch(f -> f.contains("v4-migrator bootstrap"));
    }

    @Test
    @Order(4)
    void bootstrapAppliesFlywayUpToExpectedHead() {
        final GlobalOptions opts = optsForContainer();
        opts.stagingSchema = "dt_v4_migration_bootstrap";

        final ByteArrayOutputStream capture = new ByteArrayOutputStream();
        final PrintStream origOut = System.out;
        final PrintStream origErr = System.err;
        System.setOut(new PrintStream(capture, true));
        System.setErr(new PrintStream(capture, true));
        final int exit;
        try {
            exit = new CommandLine(new V4Migrator()).execute(
                "bootstrap",
                "--target-url", container.getJdbcUrl(),
                "--target-user", container.getUsername(),
                "--target-pass", container.getPassword(),
                "--staging-schema", opts.stagingSchema);
        } finally {
            System.setOut(origOut);
            System.setErr(origErr);
        }
        assertThat(exit).as("bootstrap output: %s", capture).isEqualTo(ExitCode.OK);

        final String head = jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT version FROM flyway_schema_history
                     WHERE success = TRUE AND version IS NOT NULL
                     ORDER BY installed_rank DESC LIMIT 1
                    """)
                .mapTo(String.class)
                .one());
        assertThat(head).isEqualTo(Preflight.EXPECTED_FLYWAY_HEAD);

        // PERMISSION catalog must be seeded by bootstrap so that downstream load phases
        // can FK-resolve permission IDs even if the operator follows the documented
        // "drop v5 schema, re-bootstrap, re-run load" recovery (issue #6217).
        final long permissionCount = jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"PERMISSION\"").mapTo(Long.class).one());
        assertThat(permissionCount).isEqualTo(42L);
        final boolean hasV5OnlyPermission = jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT EXISTS (
                        SELECT 1 FROM "PERMISSION"
                         WHERE "NAME" = 'PORTFOLIO_ACCESS_CONTROL_BYPASS')
                    """)
                .mapTo(Boolean.class).one());
        assertThat(hasV5OnlyPermission).isTrue();

        // Default-mode preflight now passes (schema applied, no user data, no PERMISSION pre-seed needed).
        final PreflightResult after = new Preflight(jdbi(), null, opts, Mode.DEFAULT).run();
        assertThat(after.ok())
            .as("default preflight should pass after bootstrap; failures: %s", after.failures())
            .isTrue();
    }

    @Test
    @Order(5)
    void shouldRemainIdempotentWhenBootstrapInvokedTwice() {
        final GlobalOptions opts = optsForContainer();
        opts.stagingSchema = "dt_v4_migration_bootstrap";

        final long countBefore = jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"PERMISSION\"").mapTo(Long.class).one());

        final ByteArrayOutputStream capture = new ByteArrayOutputStream();
        final PrintStream origOut = System.out;
        final PrintStream origErr = System.err;
        System.setOut(new PrintStream(capture, true));
        System.setErr(new PrintStream(capture, true));
        final int exit;
        try {
            exit = new CommandLine(new V4Migrator()).execute(
                "bootstrap",
                "--target-url", container.getJdbcUrl(),
                "--target-user", container.getUsername(),
                "--target-pass", container.getPassword(),
                "--staging-schema", opts.stagingSchema);
        } finally {
            System.setOut(origOut);
            System.setErr(origErr);
        }
        assertThat(exit).as("second bootstrap output: %s", capture).isEqualTo(ExitCode.OK);

        final long countAfter = jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"PERMISSION\"").mapTo(Long.class).one());
        assertThat(countAfter).isEqualTo(countBefore);
    }

    private GlobalOptions optsForContainer() {
        final GlobalOptions opts = new GlobalOptions();
        opts.targetUrl = container.getJdbcUrl();
        opts.targetUser = container.getUsername();
        opts.targetPass = container.getPassword();
        opts.stagingSchema = "dt_v4_migration_pre_bootstrap";
        opts.logLevel = "INFO";
        return opts;
    }

    private Jdbi jdbi() {
        return Jdbi.create(container.getJdbcUrl(), container.getUsername(), container.getPassword());
    }
}
