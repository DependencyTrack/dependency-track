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
package org.dependencytrack.v4migrator.extract;

import org.dependencytrack.v4migrator.TableMigration;
import org.dependencytrack.v4migrator.TableRegistry;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.state.StagingSchema;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pipeline §3.
 */
public final class ExtractPhase {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtractPhase.class);

    private final GlobalOptions options;
    private final SourceOptions source;
    private final Jdbi target;
    private final long sampleRowsPerTable;
    private final int metricsRetentionDays;

    public ExtractPhase(final GlobalOptions options, final SourceOptions source, final Jdbi target,
                        final int metricsRetentionDays) {
        this(options, source, target, Long.MAX_VALUE, metricsRetentionDays);
    }

    public ExtractPhase(final GlobalOptions options, final SourceOptions source,
                        final Jdbi target, final long sampleRowsPerTable,
                        final int metricsRetentionDays) {
        this.options = options;
        this.source = source;
        this.target = target;
        this.sampleRowsPerTable = sampleRowsPerTable;
        this.metricsRetentionDays = metricsRetentionDays;
    }

    public void run() throws Exception {
        final SourceExtractor extractor = SourceExtractor.forSource(source);
        new StagingSchema(target, options.stagingSchema).ensure();

        invalidateDownstream();

        MetricsRetention.resolveAndPersist(metricsRetentionDays, options, target);

        target.useHandle(h -> {
            for (final TableMigration t : TableRegistry.extracted()) {
                h.execute(t.srcCreateDdl().formatted(options.stagingSchema));
                h.execute("TRUNCATE \"%s\".src_%s".formatted(options.stagingSchema, t.name()));
            }
        });

        final long start = System.nanoTime();
        long totalRows = 0;
        int tableCount = 0;
        for (final TableMigration t : TableRegistry.extracted()) {
            totalRows += extractOne(t, extractor);
            tableCount++;
        }
        final long ms = (System.nanoTime() - start) / 1_000_000;
        LOGGER.info("Extract phase completed: {} table(s), {} row(s) in {} ms", tableCount, totalRows, ms);
    }

    /**
     * Re-running extract invalidates downstream artefacts per pipeline §4.2: drop every
     * {@code tgt_*} table, every canonical-id map, truncate probes, and clear
     * {@code migration_state} rows for downstream phases.
     */
    private void invalidateDownstream() {
        target.useHandle(h -> {
            h.execute("DELETE FROM \"%s\".migration_state WHERE phase IN ('TRANSFORM', 'LOAD')"
                .formatted(options.stagingSchema));
            dropTablesMatching(h, "tgt\\_%", true);
            dropTablesMatching(h, "%\\_canonical_id_map", false);
            for (final String probe : org.dependencytrack.v4migrator.state.StagingSchema.PROBE_TABLES) {
                h.execute("TRUNCATE \"%s\".\"%s\"".formatted(options.stagingSchema, probe));
            }
        });
    }

    private void dropTablesMatching(final org.jdbi.v3.core.Handle h, final String pattern,
                                    final boolean escape) {
        final String escapeClause = escape ? " ESCAPE '\\'" : "";
        final java.util.List<String> tables = h.createQuery("""
                SELECT table_name FROM information_schema.tables
                 WHERE table_schema = :s
                   AND table_name LIKE :p
                """ + escapeClause)
            .bind("s", options.stagingSchema)
            .bind("p", pattern)
            .mapTo(String.class)
            .list();
        for (final String t : tables) {
            h.execute("DROP TABLE IF EXISTS \"%s\".\"%s\""
                .formatted(options.stagingSchema, t));
        }
    }

    private long extractOne(final TableMigration t, final SourceExtractor extractor) throws Exception {
        LOGGER.info("Extracting {}", t.name());
        final long start = System.nanoTime();
        markState(t.name(), "IN_PROGRESS", 0);
        try {
            final long rows = extractor.extract(t, options.stagingSchema, target, sampleRowsPerTable);
            markState(t.name(), "COMPLETED", rows);
            final long ms = (System.nanoTime() - start) / 1_000_000;
            LOGGER.info("  -> {} rows in {} ms", rows, ms);
            return rows;
        } catch (final Exception e) {
            markState(t.name(), "FAILED", 0);
            throw e;
        }
    }

    private void markState(final String table, final String status, final long rows) {
        target.useHandle(h -> h.createUpdate("""
                INSERT INTO "%s".migration_state (table_name, phase, status, rows_processed, started_at, completed_at)
                VALUES (:t, 'EXTRACT', :s, :r, NOW(), CASE WHEN :s IN ('COMPLETED', 'FAILED') THEN NOW() END)
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
