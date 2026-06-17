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
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.testsupport.V4PostgresSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.dependencytrack.v4migrator.verify.VerifyPhase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs a full pipeline that exercises dedup and the malformed-UUID probe, then runs the
 * verify phase and asserts the human-readable output reports the relevant signals.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VerifyIT {

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
    void verifyReportsCountsAndProbes() throws Exception {
        source.jdbi().useHandle(h -> {
            // One good LICENSE, one malformed UUID (probed and dropped).
            h.createUpdate("""
                INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                VALUES (1, FALSE, TRUE, 'Apache 2.0', :u)
                """).bind("u", "c5b25734-69ce-4e9b-a4f3-1f0fa5b27d5f").execute();
            h.createUpdate("""
                INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                VALUES (2, FALSE, TRUE, 'Bad', :u)
                """).bind("u", "garbage").execute();

            // Two teams sharing NAME so dedup kicks in.
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Eng', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (2, 'Eng', '22222222-2222-2222-2222-222222222222')");
        });

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

        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(buf)) {
            new VerifyPhase(global, target.jdbi(), ps).run();
        }
        final String output = buf.toString();

        // Schema head OK.
        assertThat(output).contains("OK    Flyway head = " + Preflight.EXPECTED_FLYWAY_HEAD);
        // Row counts table is present, including the Note column.
        assertThat(output).contains("[Row counts]");
        assertThat(output).containsPattern("Table\\s+Source\\s+Staging\\s+v5\\s+Note");
        assertThat(output).contains("LICENSE");
        assertThat(output).contains("TEAM");
        // The two same-named teams dedup, and that reduction is explained as expected.
        assertThat(output).containsPattern("TEAM\\s+.*expected: dedup by NAME");
        // The dropped malformed LICENSE UUID is attributed to the probes section.
        assertThat(output).containsPattern("LICENSE\\s+.*see \\[Probes]");
        // Reductions are never rendered as alarmist data-loss warnings.
        assertThat(output).doesNotContain("WARN");
        // Probe section reports the malformed UUID for LICENSE.
        assertThat(output).containsPattern("LICENSE\\s+\\d+ malformed UUID\\(s\\) dropped");
        // Constraints section emits a non-zero CHECK count.
        assertThat(output).matches("(?s).*\\[Constraints].*[1-9][0-9]* CHECK constraint.*");
        // Explicit terminator so operators/automation can detect completion.
        assertThat(output).contains("== verify complete ==");
    }

    /**
     * The migration guide recommends running verify directly after bootstrap, when no staging schema
     * exists and only the PERMISSION catalog is seeded. That workflow must not surface spurious
     * discrepancy warnings. A freshly started target container mirrors that post-bootstrap state.
     */
    @Test
    void verifyAfterBootstrapEmitsNoDiscrepancyWarnings() {
        try (final V5TargetContainer freshTarget = new V5TargetContainer().start()) {
            final GlobalOptions global = new GlobalOptions();
            global.targetUrl = freshTarget.jdbcUrl();
            global.targetUser = freshTarget.username();
            global.targetPass = freshTarget.password();
            global.stagingSchema = "dt_v4_migration";
            global.logLevel = "INFO";

            final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try (PrintStream ps = new PrintStream(buf)) {
                new VerifyPhase(global, freshTarget.jdbi(), ps).run();
            }
            final String output = buf.toString();

            assertThat(output).contains("[Row counts]");
            assertThat(output).doesNotContain("WARN");
            assertThat(output).contains("== verify complete ==");
        }
    }
}
