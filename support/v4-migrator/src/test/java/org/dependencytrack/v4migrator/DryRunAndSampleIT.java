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

import org.dependencytrack.v4migrator.testsupport.V4PostgresSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the {@code --dry-run} and {@code --sample N} CLI flags end-to-end.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DryRunAndSampleIT {

    private V4PostgresSource source;
    private V5TargetContainer target;

    @BeforeAll
    void start() {
        source = new V4PostgresSource().start();
        target = new V5TargetContainer().start();
        seedLicenses(3);
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
    void dryRunExtractPrintsPlanAndMakesNoTargetWrites() {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int exit = invoke(out,
            "extract",
            "--target-url", target.jdbcUrl(),
            "--target-user", target.username(),
            "--target-pass", target.password(),
            "--source-url", source.jdbcUrl(),
            "--source-user", source.username(),
            "--source-pass", source.password(),
            "--metrics-retention-days", "90",
            "--dry-run");

        assertThat(exit).isEqualTo(0);

        final String output = out.toString();
        assertThat(output).contains("Dry-run: preflight passed.");
        assertThat(output).contains("Phase:  extract");
        assertThat(output).contains("Source: " + source.jdbcUrl());
        assertThat(output).contains("Tables to extract");
        assertThat(output).contains("- LICENSE");

        // Dry-run must not have created the staging schema.
        final boolean stagingExists = target.jdbi().withHandle(h ->
            h.createQuery("SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'dt_v4_migration')")
                .mapTo(Boolean.class)
                .one());
        assertThat(stagingExists).isFalse();
    }

    @Test
    void runWithSampleCapsRowsPerTable() {
        // Fresh container state would be nice; instead truncate v5 LICENSE between tests.
        target.jdbi().useHandle(h -> {
            h.execute("DROP SCHEMA IF EXISTS \"dt_v4_migration\" CASCADE");
            h.execute("TRUNCATE \"LICENSE\" CASCADE");
        });

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int exit = invoke(out,
            "run",
            "--target-url", target.jdbcUrl(),
            "--target-user", target.username(),
            "--target-pass", target.password(),
            "--source-url", source.jdbcUrl(),
            "--source-user", source.username(),
            "--source-pass", source.password(),
            "--metrics-retention-days", "90",
            "--sample", "1");

        assertThat(exit).isEqualTo(0);

        final Long count = target.jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"LICENSE\"").mapTo(Long.class).one());
        assertThat(count).isEqualTo(1L);
    }

    private void seedLicenses(final int n) {
        source.jdbi().useHandle(h -> {
            for (int i = 1; i <= n; i++) {
                h.createUpdate("""
                        INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                        VALUES (:id, FALSE, TRUE, :name, :u)
                    """)
                    .bind("id", i)
                    .bind("name", "License-" + i)
                    .bind("u", UUID.randomUUID().toString())
                    .execute();
            }
        });
    }

    private static int invoke(final ByteArrayOutputStream capture, final String... args) {
        final PrintStream originalOut = System.out;
        final PrintStream originalErr = System.err;
        final PrintStream replacement = new PrintStream(capture, true);
        System.setOut(replacement);
        System.setErr(replacement);
        try {
            return new CommandLine(new V4Migrator()).execute(args);
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }
}
