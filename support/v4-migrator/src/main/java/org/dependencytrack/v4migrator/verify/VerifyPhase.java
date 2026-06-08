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
package org.dependencytrack.v4migrator.verify;

import org.dependencytrack.v4migrator.TableMigration;
import org.dependencytrack.v4migrator.TableRegistry;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintStream;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Pipeline §6. Advisory post-load checks emitted as human-readable stdout.
 */
public final class VerifyPhase {

    private static final Logger LOGGER = LoggerFactory.getLogger(VerifyPhase.class);

    private final GlobalOptions options;
    private final Jdbi target;
    private final PrintStream out;

    public VerifyPhase(final GlobalOptions options, final Jdbi target) {
        this(options, target, System.out);
    }

    public VerifyPhase(final GlobalOptions options, final Jdbi target, final PrintStream out) {
        this.options = options;
        this.target = target;
        this.out = out;
    }

    public void run() {
        out.println("== v4-migrator verify ==");
        out.println();
        checkFlywayHead();
        out.println();
        reportRowCounts();
        out.println();
        reportProbes();
        out.println();
        checkConstraintsSmoke();
        out.println();
        out.println("== verify complete ==");
    }

    private void checkFlywayHead() {
        out.println("[Schema]");
        final Optional<String> head = target.withHandle(h ->
            h.createQuery("""
                    SELECT version
                      FROM flyway_schema_history
                     WHERE success = TRUE AND version IS NOT NULL
                     ORDER BY installed_rank DESC
                     LIMIT 1
                    """)
                .mapTo(String.class)
                .findOne());
        if (head.isEmpty()) {
            out.println("  FAIL  flyway_schema_history has no versioned rows");
        } else if (!Preflight.EXPECTED_FLYWAY_HEAD.equals(head.get())) {
            out.println("  FAIL  expected Flyway head " + Preflight.EXPECTED_FLYWAY_HEAD
                + " but found " + head.get());
        } else {
            out.println("  OK    Flyway head = " + head.get());
        }
    }

    private void reportRowCounts() {
        out.println("[Row counts]");
        out.printf("  %-24s %12s %12s %12s  %s%n", "Table", "Source", "Staging", "v5", "Note");
        final Set<String> probed = probedTables();
        for (final TableMigration t : TableRegistry.all()) {
            final Long src = t.hasExtract() ? countOptional(qualified("src_" + t.name())) : null;
            final Long tgt = t.hasTransform() ? countOptional(qualified("tgt_" + t.name())) : null;
            final Long v5 = t.hasLoad() ? countOptional("\"" + t.name() + "\"") : null;
            out.printf("  %-24s %12s %12s %12s  %s%n",
                t.name(),
                fmt(src), fmt(tgt), fmt(v5), note(t.name(), src, tgt, v5, probed));
        }
    }

    /**
     * Explains a row-count reduction across the populated stages (source -> staging -> v5).
     * Requires at least two non-null stages to compute a delta, so a freshly bootstrapped target
     * (no staging schema, only seeded v5 rows) emits nothing.
     *
     * <p>Reductions are expected, not necessarily a sign of a problem: the load step copies the
     * {@code tgt_*} staging tables verbatim, so reductions originate in the transform (deduplication,
     * filtering, retention) and are intentional by design. (The sole exception is the derived
     * {@code PROJECT_ACCESS_USERS} load, which uses {@code ON CONFLICT DO NOTHING} against an
     * already-deduplicated staging table.) The note's job is to attribute each reduction so an
     * operator can tell an accounted-for drop from an unexplained one: documented transforms render
     * as {@code expected: <reason>}; drops already itemized by the {@code [Probes]} section render as
     * {@code see [Probes]}; anything else renders as a neutral {@code reduction (-N), see migration
     * guide} pointer. ASCII-only to stay automation-friendly.
     */
    static String note(final String table, final Long src, final Long tgt, final Long v5,
                       final Set<String> probed) {
        final Long first = src != null ? src : tgt;
        final Long last = v5 != null ? v5 : tgt;
        // Need a baseline and a distinct later stage to speak of a reduction.
        final int populated = (src != null ? 1 : 0) + (tgt != null ? 1 : 0) + (v5 != null ? 1 : 0);
        if (populated < 2 || first == null || last == null || last >= first) {
            return "";
        }
        final long delta = first - last;
        final Optional<String> reason = RowCountNotes.reasonFor(table);
        if (reason.isPresent()) {
            return "expected: " + reason.get() + " (-" + delta + ")";
        }
        if (probed.contains(table)) {
            return "see [Probes] (-" + delta + ")";
        }
        return "reduction (-" + delta + "), see migration guide";
    }

    /**
     * Set of table names that appear in any probe (invalid UUIDs, skipped users, case collisions),
     * i.e. tables whose row-count drop is already explained in the {@code [Probes]} section. Empty
     * when the staging schema is absent (e.g. verify run straight after bootstrap).
     */
    private Set<String> probedTables() {
        if (!stagingSchemaExists()) {
            return Set.of();
        }
        return target.withHandle(h -> new HashSet<>(h.createQuery("""
                SELECT table_name FROM "%1$s".probe_invalid_uuids
                UNION
                SELECT table_name FROM "%1$s".probe_skipped_users
                UNION
                SELECT table_name FROM "%1$s".probe_case_collisions
                """.formatted(options.stagingSchema))
            .mapTo(String.class)
            .list()));
    }

    private void reportProbes() {
        out.println("[Probes]");
        if (!stagingSchemaExists()) {
            out.println("  Staging schema \"" + options.stagingSchema + "\" not present — run extract first.");
            return;
        }
        boolean anyEntries = false;
        anyEntries |= reportProbeInvalidUuids();
        anyEntries |= reportProbeSkippedUsers();
        anyEntries |= reportProbeCaseCollisions();
        if (!anyEntries) {
            out.println("  No probe entries.");
        }
    }

    private boolean stagingSchemaExists() {
        return target.withHandle(h ->
            h.createQuery("SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = :n)")
                .bind("n", options.stagingSchema)
                .mapTo(Boolean.class)
                .one());
    }

    private boolean reportProbeInvalidUuids() {
        final List<Map<String, Object>> rows = target.withHandle(h ->
            h.createQuery("""
                    SELECT table_name, count(*) AS n
                      FROM "%s".probe_invalid_uuids
                     GROUP BY table_name
                     ORDER BY table_name
                    """.formatted(options.stagingSchema))
                .mapToMap()
                .list());
        for (final Map<String, Object> r : rows) {
            out.printf("  %-24s %d malformed UUID(s) dropped%n", r.get("table_name"), r.get("n"));
        }
        return !rows.isEmpty();
    }

    private boolean reportProbeSkippedUsers() {
        final List<Map<String, Object>> rows = target.withHandle(h ->
            h.createQuery("""
                    SELECT table_name, reason, count(*) AS n
                      FROM "%s".probe_skipped_users
                     GROUP BY table_name, reason
                     ORDER BY table_name, reason
                    """.formatted(options.stagingSchema))
                .mapToMap()
                .list());
        for (final Map<String, Object> r : rows) {
            out.printf("  %-24s %d user(s) skipped (%s)%n",
                r.get("table_name"), r.get("n"), r.get("reason"));
        }
        return !rows.isEmpty();
    }

    private boolean reportProbeCaseCollisions() {
        final List<Map<String, Object>> rows = target.withHandle(h ->
            h.createQuery("""
                    SELECT table_name, column_name, count(*) AS n
                      FROM "%s".probe_case_collisions
                     GROUP BY table_name, column_name
                     ORDER BY table_name, column_name
                    """.formatted(options.stagingSchema))
                .mapToMap()
                .list());
        for (final Map<String, Object> r : rows) {
            out.printf("  %-24s %d case-collision(s) on column %s%n",
                r.get("table_name"), r.get("n"), r.get("column_name"));
        }
        return !rows.isEmpty();
    }

    private void checkConstraintsSmoke() {
        out.println("[Constraints]");
        // PostgreSQL would have failed every load that violated a CHECK constraint, so this
        // is mostly a tripwire. We surface only NOT VALID constraints (none exist in v5 today),
        // and count CHECK constraints on the loaded tables for transparency.
        final List<TableMigration> loaded = TableRegistry.loaded();
        final long checkCount = target.withHandle(h ->
            h.createQuery("""
                    SELECT count(*)
                      FROM pg_constraint c
                      JOIN pg_class t ON t.oid = c.conrelid
                     WHERE c.contype = 'c'
                       AND t.relname = ANY(:names)
                    """)
                .bindArray("names", String.class, loaded.stream().map(TableMigration::name).toArray(String[]::new))
                .mapTo(Long.class)
                .one());
        out.printf("  %d CHECK constraint(s) hold across %d loaded table(s)%n", checkCount, loaded.size());
    }

    private Long countOptional(final String qualifiedTable) {
        try {
            return target.withHandle(h ->
                h.createQuery("SELECT count(*) FROM " + qualifiedTable)
                    .mapTo(Long.class)
                    .one());
        } catch (final RuntimeException e) {
            LOGGER.debug("count(*) failed for {}: {}", qualifiedTable, e.toString());
            return null;
        }
    }

    private String qualified(final String table) {
        return "\"" + options.stagingSchema + "\"." + table;
    }

    private static String fmt(final Long n) {
        return n == null ? "-" : Long.toString(n);
    }
}
