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
package org.dependencytrack.v4migrator.preflight;

import org.dependencytrack.v4migrator.ExitCode;
import org.dependencytrack.v4migrator.config.Connections;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.source.SourceFlavor;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Pre-flight checks per pipeline design §9.
 *
 * <p>Runs the checks applicable to the requested phase. {@code source} may be {@code null} for
 * commands that do not touch the source (transform / load / verify / cleanup).
 */
public final class Preflight {

    public static final String EXPECTED_FLYWAY_HEAD = "202605111028";

    private static final Logger LOGGER = LoggerFactory.getLogger(Preflight.class);

    /**
     * Pre-bootstrap mode skips every check that depends on the v5 schema existing on the
     * target. The {@code bootstrap} subcommand uses this mode because it runs against a
     * fresh Postgres database that has not yet had Flyway applied.
     */
    public enum Mode {
        DEFAULT,
        PRE_BOOTSTRAP,
        /**
         * Same as {@link #DEFAULT} but skips the "target tables must be empty" gate.
         * Used by {@code verify}, which by definition runs after a successful load.
         */
        POST_LOAD
    }

    private final Jdbi targetJdbi;
    private final @Nullable SourceOptions source;
    private final GlobalOptions options;
    private final Mode mode;

    public Preflight(final Jdbi targetJdbi, final @Nullable SourceOptions source, final GlobalOptions options) {
        this(targetJdbi, source, options, Mode.DEFAULT);
    }

    public Preflight(final Jdbi targetJdbi, final @Nullable SourceOptions source, final GlobalOptions options,
                     final Mode mode) {
        this.targetJdbi = targetJdbi;
        this.source = source;
        this.options = options;
        this.mode = mode;
    }

    public PreflightResult run() {
        final List<String> failures = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();

        checkTargetVersion(failures);
        if (mode != Mode.PRE_BOOTSTRAP) {
            checkTargetExtensions(failures);
            if (isV5SchemaApplied(failures)) {
                checkFlywayHead(failures);
                if (mode == Mode.DEFAULT) {
                    checkTargetEmpty(failures);
                }
            }
        }
        checkTargetSettings(warnings);
        checkStagingSchemaState(failures);

        if (source != null) {
            checkSource(failures);
        }

        int exitCode = ExitCode.OK;
        if (!failures.isEmpty()) {
            exitCode = pickExitCode(failures);
        }
        for (final String warn : warnings) {
            LOGGER.warn(warn);
        }
        for (final String fail : failures) {
            LOGGER.error(fail);
        }
        return new PreflightResult(exitCode, failures, warnings);
    }

    private void checkTargetVersion(final List<String> failures) {
        try {
            final Integer major = targetJdbi.withHandle(h ->
                h.createQuery("SELECT current_setting('server_version_num')::int / 10000")
                    .mapTo(Integer.class)
                    .one());
            if (major < 13) {
                failures.add("Target PostgreSQL must be version 13 or newer (gen_random_uuid); found " + major);
            }
        } catch (final RuntimeException e) {
            failures.add("Could not query target PostgreSQL version: " + e.getMessage());
        }
    }

    private void checkTargetExtensions(final List<String> failures) {
        try {
            final boolean trgm = targetJdbi.withHandle(h ->
                h.createQuery("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
                    .mapTo(Boolean.class)
                    .one());
            if (!trgm) {
                failures.add("Target is missing the pg_trgm extension. The v5 schema bootstrap installs it; "
                    + "ensure the schema is applied before running the migrator.");
            }
        } catch (final RuntimeException e) {
            failures.add("Could not enumerate target PostgreSQL extensions: " + e.getMessage());
        }
    }

    /**
     * Cheap signal for "has the v5 schema been bootstrapped at all?". If
     * {@code flyway_schema_history} doesn't exist, the empty-table and PERMISSION-seed checks
     * would cascade into a wall of "relation does not exist" errors that obscure the one
     * actionable failure: the operator forgot to run the v5 apiserver against this target
     * to bootstrap Flyway.
     */
    private boolean isV5SchemaApplied(final List<String> failures) {
        try {
            final boolean present = targetJdbi.withHandle(h ->
                h.createQuery("""
                        SELECT EXISTS (
                            SELECT 1 FROM information_schema.tables
                             WHERE table_name = 'flyway_schema_history')
                        """)
                    .mapTo(Boolean.class)
                    .one());
            if (!present) {
                failures.add("Target has no flyway_schema_history; run "
                    + "'v4-migrator bootstrap' against this database first to apply the v5 schema.");
            }
            return present;
        } catch (final RuntimeException e) {
            failures.add("Could not inspect target schema: " + e.getMessage());
            return false;
        }
    }

    private void checkFlywayHead(final List<String> failures) {
        try {
            final String head = targetJdbi.withHandle(h ->
                h.createQuery("""
                        SELECT version
                          FROM flyway_schema_history
                         WHERE success = TRUE
                           AND version IS NOT NULL
                         ORDER BY installed_rank DESC
                         LIMIT 1
                        """)
                    .mapTo(String.class)
                    .findOne()
                    .orElse(null));
            if (head == null) {
                failures.add("Target flyway_schema_history is empty; run 'v4-migrator bootstrap' first.");
            } else if (!EXPECTED_FLYWAY_HEAD.equals(head)) {
                failures.add("Target Flyway head is '" + head + "' but expected '" + EXPECTED_FLYWAY_HEAD + "'.");
            }
        } catch (final RuntimeException e) {
            failures.add("Could not read flyway_schema_history: " + e.getMessage());
        }
    }

    /**
     * Refuse to operate against a v5 cluster that already has user data.
     * Checks a small set of high-trust tables. Flyway-installed seed data
     * (e.g. default permissions) is permitted.
     */
    private void checkTargetEmpty(final List<String> failures) {
        final String[] mustBeEmpty = {
            "\"PROJECT\"", "\"COMPONENT\"", "\"VULNERABILITY\"", "\"BOM\"", "\"USER\""
        };
        for (final String table : mustBeEmpty) {
            try {
                final Long count = targetJdbi.withHandle(h ->
                    h.createQuery("SELECT count(*) FROM " + table)
                        .mapTo(Long.class)
                        .one());
                if (count > 0) {
                    failures.add("Target table " + table + " is not empty (count=" + count
                        + "). Refusing to run against a populated v5 cluster.");
                }
            } catch (final RuntimeException e) {
                failures.add("Could not count " + table + ": " + e.getMessage());
            }
        }
    }

    private void checkTargetSettings(final List<String> warnings) {
        recommendSetting("max_wal_size", 4L * 1024 * 1024 * 1024, warnings);
        recommendSetting("max_locks_per_transaction", 128, warnings);
    }

    private void recommendSetting(final String name, final long minimum, final List<String> warnings) {
        try {
            final String raw = targetJdbi.withHandle(h ->
                h.createQuery("SELECT current_setting(:name, TRUE)")
                    .bind("name", name)
                    .mapTo(String.class)
                    .findOne()
                    .orElse(null));
            if (raw == null) {
                return;
            }
            if ("max_locks_per_transaction".equals(name)) {
                final int val = Integer.parseInt(raw);
                if (val < minimum) {
                    warnings.add("max_locks_per_transaction=" + val
                        + " may be insufficient for metrics partition attaches. Recommended: ≥ " + minimum + ".");
                }
                return;
            }
            // size-shaped settings ('1GB', '2048MB', etc.); leave parsing best-effort and silent on failure.
            final Long bytes = parsePgSizeSetting(raw);
            if (bytes != null && bytes < minimum) {
                warnings.add(name + "=" + raw + " may produce WAL pressure during load. Recommended: ≥ "
                    + (minimum / (1024 * 1024 * 1024)) + "GB.");
            }
        } catch (final RuntimeException e) {
            // Non-fatal; preflight warnings are advisory.
        }
    }

    private static @Nullable Long parsePgSizeSetting(final String raw) {
        // PostgreSQL returns settings like 'max_wal_size' via current_setting() in human form,
        // e.g. '1GB'. pg_settings.unit gives the underlying unit. For preflight we accept the
        // string form and parse common suffixes.
        try {
            final String trimmed = raw.trim().toUpperCase();
            if (trimmed.endsWith("GB")) {
                return Long.parseLong(trimmed.substring(0, trimmed.length() - 2).trim()) * 1024L * 1024 * 1024;
            }
            if (trimmed.endsWith("MB")) {
                return Long.parseLong(trimmed.substring(0, trimmed.length() - 2).trim()) * 1024L * 1024;
            }
            if (trimmed.endsWith("KB")) {
                return Long.parseLong(trimmed.substring(0, trimmed.length() - 2).trim()) * 1024L;
            }
            return Long.parseLong(trimmed);
        } catch (final NumberFormatException e) {
            return null;
        }
    }

    private void checkStagingSchemaState(final List<String> failures) {
        try {
            final Boolean exists = targetJdbi.withHandle(h ->
                h.createQuery("SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = :name)")
                    .bind("name", options.stagingSchema)
                    .mapTo(Boolean.class)
                    .one());
            if (Boolean.TRUE.equals(exists)) {
                final Boolean stateTable = targetJdbi.withHandle(h ->
                    h.createQuery("""
                            SELECT EXISTS (
                                SELECT 1 FROM information_schema.tables
                                WHERE table_schema = :s AND table_name = 'migration_state')
                            """)
                        .bind("s", options.stagingSchema)
                        .mapTo(Boolean.class)
                        .one());
                if (!Boolean.TRUE.equals(stateTable)) {
                    failures.add("Staging schema '" + options.stagingSchema
                        + "' exists but does not contain migration_state. Drop the schema or pick a different one.");
                }
            }
        } catch (final RuntimeException e) {
            failures.add("Could not inspect staging schema: " + e.getMessage());
        }
    }

    private void checkSource(final List<String> failures) {
        final SourceFlavor flavor;
        try {
            flavor = SourceFlavor.fromJdbcUrl(source.sourceUrl);
        } catch (final IllegalArgumentException e) {
            failures.add(e.getMessage());
            return;
        }

        try (Connection conn = Connections.openSource(source)) {
            checkSourceSchemaMarker(conn, flavor, failures);
        } catch (final SQLException e) {
            failures.add("Could not connect to source database: " + e.getMessage());
        }
    }

    private static void checkSourceSchemaMarker(final Connection conn, final SourceFlavor flavor,
                                                final List<String> failures) {
        final String sql = switch (flavor) {
            case POSTGRESQL -> "SELECT to_regclass('public.\"PROJECT\"') IS NOT NULL";
            case MSSQL -> "SELECT CASE WHEN OBJECT_ID('dbo.PROJECT','U') IS NOT NULL THEN 1 ELSE 0 END";
        };
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            final boolean present = rs.next() && rs.getBoolean(1);
            if (!present) {
                failures.add("Source database does not contain expected v4 table PROJECT; "
                    + "wrong database or schema?");
            }
        } catch (final SQLException e) {
            failures.add("Could not inspect source schema: " + e.getMessage());
        }
    }

    private static int pickExitCode(final List<String> failures) {
        for (final String f : failures) {
            if (f.contains("Flyway head")) {
                return ExitCode.SCHEMA_VERSION_MISMATCH;
            }
        }
        return ExitCode.PREFLIGHT_FAILED;
    }
}
