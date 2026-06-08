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
package org.dependencytrack.v4migrator.load;

import org.dependencytrack.v4migrator.TableMigration;
import org.dependencytrack.v4migrator.TableRegistry;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.state.StagingSchema;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Pipeline §5.
 */
public final class LoadPhase {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoadPhase.class);

    /**
     * Tables that have IDENTITY columns whose sequence must be reset after load.
     */
    private static final List<String> IDENTITY_TABLES_TO_RESET = List.of(
        "LICENSE", "LICENSEGROUP", "TEAM", "TAG", "OIDCGROUP", "REPOSITORY", "PROJECT", "USER",
        "NOTIFICATIONPUBLISHER", "NOTIFICATIONRULE", "POLICY", "POLICYCONDITION",
        "PROJECT_METADATA", "COMPONENT", "SERVICECOMPONENT",
        "APIKEY", "MAPPEDLDAPGROUP", "MAPPEDOIDCGROUP",
        "VULNERABILITY", "VULNERABLESOFTWARE", "VULNERABILITYMETRICS",
        "AFFECTEDVERSIONATTRIBUTION", "BOM", "VEX",
        "FINDINGATTRIBUTION", "POLICYVIOLATION", "ANALYSIS", "ANALYSISCOMMENT",
        "VIOLATIONANALYSIS", "VIOLATIONANALYSISCOMMENT",
        "CONFIGPROPERTY", "PROJECT_PROPERTY", "COMPONENT_PROPERTY"
    );

    private final GlobalOptions options;
    private final Jdbi target;
    private final boolean dropStagingAfter;

    public LoadPhase(final GlobalOptions options, final Jdbi target,
                     final boolean dropStagingAfter) {
        this.options = options;
        this.target = target;
        this.dropStagingAfter = dropStagingAfter;
    }

    public void run() {
        final StagingSchema staging = new StagingSchema(target, options.stagingSchema);
        staging.ensure();

        final long start = System.nanoTime();
        long totalRows = 0;
        int tableCount = 0;
        preLoad();
        for (final TableMigration t : TableRegistry.loaded()) {
            totalRows += loadOne(t);
            tableCount++;
        }
        postLoad();

        if (dropStagingAfter) {
            LOGGER.info("Dropping staging schema (--drop-staging set).");
            staging.drop();
        }

        final long ms = (System.nanoTime() - start) / 1_000_000;
        LOGGER.info("Load phase completed: {} table(s), {} row(s) in {} ms", tableCount, totalRows, ms);
    }

    private void preLoad() {
        // Disable PROJECT_HIERARCHY maintenance triggers on PROJECT so the bulk PROJECT load
        // does not run the per-row ancestor walk; we load the pre-built closure directly.
        // Disable PROJECT_ACCESS_USERS write-blocking trigger so the derived backfill can
        // insert directly; v5 normally maintains this table exclusively via triggers.
        // Disable the PROJECT_ACCESS_USERS-populating triggers on PROJECT_ACCESS_TEAMS and
        // USERS_TEAMS so the migrator's pre-computed tgt_project_access_users remains the
        // sole source of truth for the PROJECT_ACCESS_USERS load; otherwise those triggers
        // fire during the parent loads and shadow the direct INSERT (which then reports 0
        // rows due to ON CONFLICT DO NOTHING).
        target.useHandle(h -> {
            h.execute("ALTER TABLE \"PROJECT\" DISABLE TRIGGER USER");
            h.execute("ALTER TABLE \"PROJECT_ACCESS_USERS\" DISABLE TRIGGER USER");
            h.execute("ALTER TABLE \"PROJECT_ACCESS_TEAMS\" DISABLE TRIGGER USER");
            h.execute("ALTER TABLE \"USERS_TEAMS\" DISABLE TRIGGER USER");
        });
        prepareMetricsPartitions();
    }

    private void postLoad() {
        LOGGER.info("Finalizing load: re-enabling triggers and resetting identity sequences");
        target.useHandle(h -> {
            h.execute("ALTER TABLE \"PROJECT\" ENABLE TRIGGER USER");
            h.execute("ALTER TABLE \"PROJECT_ACCESS_USERS\" ENABLE TRIGGER USER");
            h.execute("ALTER TABLE \"PROJECT_ACCESS_TEAMS\" ENABLE TRIGGER USER");
            h.execute("ALTER TABLE \"USERS_TEAMS\" ENABLE TRIGGER USER");
        });

        // Restart IDENTITY sequence for each loaded table that preserved v4 IDs.
        target.useHandle(h -> {
            for (final String t : IDENTITY_TABLES_TO_RESET) {
                h.execute("""
                    SELECT setval(pg_get_serial_sequence('"%1$s"', 'ID'),
                                  COALESCE((SELECT MAX("ID") FROM "%1$s"), 1), true)
                    """.formatted(t));
            }
        });
        // ANALYZE every loaded table for fresh planner statistics.
        final List<TableMigration> loaded = TableRegistry.loaded();
        LOGGER.info("Analyzing {} loaded table(s)", loaded.size());
        target.useHandle(h -> {
            for (final TableMigration t : loaded) {
                h.execute("ANALYZE \"%s\"".formatted(t.name()));
            }
        });
        // Refresh PORTFOLIOMETRICS_GLOBAL after PROJECTMETRICS is in place.
        LOGGER.info("Refreshing PORTFOLIOMETRICS_GLOBAL materialized view");
        target.useHandle(h -> h.execute("REFRESH MATERIALIZED VIEW \"PORTFOLIOMETRICS_GLOBAL\""));
        LOGGER.info("Applying v5.7.0 cleanup deletes");
        replayV570CleanupDeletes();
    }

    /**
     * Pre-creates daily RANGE partitions on {@code DEPENDENCYMETRICS} and {@code PROJECTMETRICS}
     * spanning from the retention cutoff date to tomorrow (one buffer day for future-dated rows).
     * Idempotent: existing partitions are kept; attaches are no-ops on already-attached children.
     * Partitions are created LOGGED to match the partitioned parent. Chunked at 32 attaches per
     * transaction to respect {@code max_locks_per_transaction}.
     */
    private void prepareMetricsPartitions() {
        final Optional<String> cutoffStr = target.withHandle(h ->
            h.createQuery("""
                    SELECT value FROM "%s".migration_config
                     WHERE key = 'metrics_retention_cutoff_at'
                    """.formatted(options.stagingSchema))
                .mapTo(String.class)
                .findOne());
        if (cutoffStr.isEmpty()) {
            LOGGER.info("No metrics retention cutoff recorded; skipping partition pre-creation.");
            return;
        }
        final LocalDate from = OffsetDateTime.parse(cutoffStr.get()).toLocalDate();
        final LocalDate to = LocalDate.now(ZoneOffset.UTC).plusDays(1);
        final List<LocalDate> days = new ArrayList<>();
        for (LocalDate d = from; !d.isAfter(to); d = d.plusDays(1)) {
            days.add(d);
        }
        LOGGER.info("Pre-creating metrics partitions for {} day(s) from {} to {}",
            days.size(), from, to);

        for (final String parent : List.of("DEPENDENCYMETRICS", "PROJECTMETRICS")) {
            // Create-then-attach in chunks of 32. Chunking limits the number of AccessExclusiveLocks
            // acquired in a single transaction.
            final int chunk = 32;
            for (int i = 0; i < days.size(); i += chunk) {
                final List<LocalDate> slice = days.subList(i, Math.min(i + chunk, days.size()));
                target.useTransaction(th -> {
                    // Pin session TZ to UTC so partition boundaries are deterministic.
                    // The v5 apiserver creates partitions via session-TZ DATE literals
                    // (MetricsDao.createMetricsPartitions); aligning here means partitions
                    // attach without overlap when v5 also runs in UTC (the documented setup).
                    th.execute("SET LOCAL TIME ZONE 'UTC'");
                    for (final LocalDate d : slice) {
                        final String child = "%s_%s".formatted(parent,
                            d.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
                        th.execute("""
                            CREATE TABLE IF NOT EXISTS "%s"
                              (LIKE "%s" INCLUDING DEFAULTS INCLUDING CONSTRAINTS)
                            """.formatted(child, parent));
                        // Skip ATTACH if the child is already a partition (already attached to
                        // this parent, e.g. by v5 maintenance jobs).
                        final boolean attached = th.createQuery("""
                                SELECT EXISTS (
                                    SELECT 1 FROM pg_inherits
                                     WHERE inhrelid = ('"' || :c || '"')::regclass
                                )
                                """)
                            .bind("c", child)
                            .mapTo(Boolean.class)
                            .one();
                        if (!attached) {
                            final LocalDate next = d.plusDays(1);
                            th.execute("""
                                ALTER TABLE "%s" ATTACH PARTITION "%s"
                                  FOR VALUES FROM ('%s') TO ('%s')
                                """.formatted(parent, child, d, next));
                        }
                    }
                });
            }
        }
    }

    /**
     * Replays the {@code CONFIGPROPERTY} and {@code PERMISSION} DELETE statements from
     * Liquibase changesets v5.7.0-15, -22, -24, -28, -30, -38, -81 against the v5 target.
     * The v5 seed already excludes these rows, so the deletes are no-ops on a fresh-v5
     * target; replayed unconditionally to handle migrated v4 data.
     */
    private void replayV570CleanupDeletes() {
        target.useTransaction(th -> {
            // v5.7.0-15
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = 'vuln.datasource'
                   AND "PROPERTYNAME" IN (
                         'extension.github.watermark'
                       , 'extension.nvd.watermark'
                       , 'extension.osv.watermarks'
                       )
                """);
            // v5.7.0-22 (part 1)
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE ("GROUPNAME", "PROPERTYNAME") IN (
                       ('integrations', 'defectdojo.sync.cadence')
                     , ('integrations', 'fortify.ssc.sync.cadence')
                     , ('integrations', 'kenna.sync.cadence')
                     , ('scanner', 'npmaudit.enabled')
                     , ('vuln-source', 'github.advisories.access.token')
                     , ('vuln-source', 'github.advisories.alias.sync.enabled')
                     , ('vuln-source', 'github.advisories.enabled')
                     , ('vuln-source', 'google.osv.alias.sync.enabled')
                     , ('vuln-source', 'google.osv.base.url')
                     , ('vuln-source', 'google.osv.enabled')
                     )
                """);
            // v5.7.0-22 (part 2)
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" IN ('search-indexes', 'task-scheduler')
                """);
            // v5.7.0-24
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE ("GROUPNAME", "PROPERTYNAME") IN (
                       ('vuln.datasource', 'extension.csaf.enabled')
                     , ('vuln.datasource', 'extension.csaf.sources')
                     )
                """);
            // v5.7.0-28
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = 'vuln.datasource'
                   AND "PROPERTYNAME" LIKE 'extension.%'
                """);
            // v5.7.0-30
            th.execute("DELETE FROM \"PERMISSION\" WHERE \"NAME\" = 'SECRET_MANAGEMENT_READ'");
            // v5.7.0-38 (part 1)
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = 'email'
                """);
            // v5.7.0-38 (part 2)
            th.execute("""
                DELETE FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = 'integrations'
                   AND "PROPERTYNAME" LIKE 'jira.%'
                """);
            // v5.7.0-81
            th.execute("DELETE FROM \"PERMISSION\" WHERE \"NAME\" = 'VIEW_BADGES'");
        });
    }

    private long loadOne(final TableMigration t) {
        LOGGER.info("Loading {} into v5", t.name());
        markState(t.name(), "IN_PROGRESS", 0);
        final long expected = expectedRows(t.name());
        try (final LoadProgressReporter reporter = new LoadProgressReporter()) {
            reporter.start(t.name(), expected);
            try {
                final int inserted = target.inTransaction(h -> h.execute(t.loadSql().formatted(options.stagingSchema)));
                markState(t.name(), "COMPLETED", inserted);
                reporter.done(inserted);
                return inserted;
            } catch (final RuntimeException e) {
                reporter.fail();
                markState(t.name(), "FAILED", 0);
                throw e;
            }
        }
    }

    /**
     * Expected upper-bound row count for the load, taken from the staging {@code tgt_*} table
     * populated by the transform phase. Returns {@code -1} if the table has no {@code tgt_*}
     * (e.g. derived loads like {@code PROJECT_ACCESS_USERS}) or the count query fails.
     */
    private long expectedRows(final String name) {
        try {
            return target.withHandle(h ->
                h.createQuery("SELECT count(*) FROM \"%s\".tgt_%s".formatted(options.stagingSchema, name))
                    .mapTo(Long.class)
                    .one());
        } catch (final RuntimeException e) {
            return -1L;
        }
    }

    private void markState(final String table, final String status, final long rows) {
        target.useHandle(h -> h.createUpdate("""
                INSERT INTO "%s".migration_state (table_name, phase, status, rows_processed, started_at, completed_at)
                VALUES (:t, 'LOAD', :s, :r, NOW(), CASE WHEN :s IN ('COMPLETED', 'FAILED') THEN NOW() END)
                ON CONFLICT (table_name, phase) DO UPDATE
                    SET status = :s,
                        rows_processed = :r,
                        completed_at = CASE WHEN :s IN ('COMPLETED', 'FAILED') THEN NOW() END
                """.formatted(options.stagingSchema))
            .bind("t", table)
            .bind("s", status)
            .bind("r", rows)
            .execute());
    }
}
