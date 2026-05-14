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
package org.dependencytrack.v4migrator.transform;

import org.dependencytrack.v4migrator.TableMigration;
import org.dependencytrack.v4migrator.TableRegistry;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.state.StagingSchema;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Pipeline §4.
 */
public final class TransformPhase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TransformPhase.class);

    private final GlobalOptions options;
    private final Jdbi target;

    public TransformPhase(final GlobalOptions options, final Jdbi target) {
        this.options = options;
        this.target = target;
    }

    public void run() {
        new StagingSchema(target, options.stagingSchema).ensure();
        // Re-running transform invalidates load state (per pipeline §4.2). The transforms
        // themselves drop and rebuild every tgt_* table; we just clear the LOAD ledger.
        target.useHandle(h -> h.execute(
            "DELETE FROM \"%s\".migration_state WHERE phase = 'LOAD'"
                .formatted(options.stagingSchema)));
        for (final TableMigration t : TableRegistry.transformed()) {
            transformOne(t);
        }
    }

    private void transformOne(final TableMigration t) {
        LOGGER.info("Transforming {}", t.name());
        final long start = System.nanoTime();
        markState(t.name(), "IN_PROGRESS");
        try {
            final String sql = t.transformSql().formatted(options.stagingSchema);
            final List<String> statements = SqlStatementSplitter.split(sql);
            target.useHandle(h -> {
                for (final String stmt : statements) {
                    h.execute(stmt);
                }
            });
            // Transform-only tables (no v5 load) may not produce a tgt_X table; their output
            // is e.g. a name-map. Count tgt_X when present, otherwise report 0 to migration_state.
            final long rows = t.hasLoad() ? countTgt(t.name()) : 0L;
            markCompleted(t.name(), rows);
            final long ms = (System.nanoTime() - start) / 1_000_000;
            if (t.hasLoad()) {
                LOGGER.info("  -> {} rows in {} ms", rows, ms);
            } else {
                LOGGER.info("  -> done in {} ms", ms);
            }
        } catch (final RuntimeException e) {
            markState(t.name(), "FAILED");
            throw e;
        }
    }

    private long countTgt(final String name) {
        return target.withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"%s\".tgt_%s".formatted(options.stagingSchema, name))
                .mapTo(Long.class)
                .one());
    }

    private void markState(final String table, final String status) {
        target.useHandle(h -> h.createUpdate("""
                INSERT INTO "%s".migration_state (table_name, phase, status, started_at)
                VALUES (:t, 'TRANSFORM', :s, NOW())
                ON CONFLICT (table_name, phase) DO UPDATE
                    SET status = :s, started_at = NOW(), completed_at = NULL, rows_processed = 0
                """.formatted(options.stagingSchema))
            .bind("t", table)
            .bind("s", status)
            .execute());
    }

    private void markCompleted(final String table, final long rows) {
        target.useHandle(h -> h.createUpdate("""
                UPDATE "%s".migration_state
                   SET status = 'COMPLETED', rows_processed = :r, completed_at = NOW()
                 WHERE table_name = :t AND phase = 'TRANSFORM'
                """.formatted(options.stagingSchema))
            .bind("t", table)
            .bind("r", rows)
            .execute());
    }
}
