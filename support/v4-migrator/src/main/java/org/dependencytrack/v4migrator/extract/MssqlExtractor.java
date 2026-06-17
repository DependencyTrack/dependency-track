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
import org.dependencytrack.v4migrator.config.Connections;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.jdbi.v3.core.Jdbi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Source extractor for Microsoft SQL Server v4.
 *
 * <p>Streams rows via a JDBC server-side cursor and writes them into the target staging
 * schema via batched JDBC INSERT. Cross-protocol means no binary COPY here; the throughput
 * is bounded by the MSSQL driver and the target row-by-row insert path. The migrator runs
 * once and offline, so this is acceptable.
 *
 * <p>Source-side notes per step 1 findings:
 * <ul>
 *   <li>MSSQL {@code DATETIME2} has no timezone; we read with a UTC {@link Calendar} so the
 *       value is reinterpreted as UTC on the way into the PG {@code timestamptz} column.</li>
 *   <li>{@code BIT} maps to Java {@code Boolean} via {@code getObject}; PG accepts boolean.</li>
 *   <li>{@code VARBINARY(MAX)} / {@code IMAGE} flow as {@code byte[]}.</li>
 * </ul>
 */
final class MssqlExtractor implements SourceExtractor {

    private static final int BATCH_SIZE = 10_000;
    private static final Calendar UTC = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

    private final SourceOptions source;
    private final String sourceSchema;

    MssqlExtractor(final SourceOptions source, final String sourceSchema) {
        this.source = source;
        this.sourceSchema = sourceSchema;
    }

    @Override
    public long extract(final TableMigration table, final String stagingSchema,
                        final Jdbi target, final long sampleLimit) throws Exception {
        final String renderedSelect = table.extractSelect().formatted(sourceSchema);
        final String selectSql = sampleLimit == Long.MAX_VALUE
            ? renderedSelect
            : applyMssqlTopLimit(renderedSelect, sampleLimit);

        try (Connection src = Connections.openSource(source)) {
            src.setAutoCommit(false);
            try (Statement stmt = src.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
                stmt.setFetchSize(BATCH_SIZE);
                try (ResultSet rs = stmt.executeQuery(selectSql)) {
                    return streamInsert(table, stagingSchema, target, rs);
                }
            }
        }
    }

    private long streamInsert(final TableMigration table, final String stagingSchema,
                              final Jdbi target, final ResultSet rs) throws Exception {
        final String quotedCols = table.extractColumns().stream()
            .map(c -> "\"" + c + "\"")
            .reduce((a, b) -> a + ", " + b)
            .orElseThrow();
        final String placeholders = "?, ".repeat(table.extractColumns().size() - 1) + "?";
        final String insertSql = "INSERT INTO \"%s\".src_%s (%s) VALUES (%s)"
            .formatted(stagingSchema, table.name(), quotedCols, placeholders);
        final ResultSetMetaData md = rs.getMetaData();
        final int colCount = md.getColumnCount();

        return target.withHandle(h -> {
            try (PreparedStatement ps = h.getConnection().prepareStatement(insertSql)) {
                long total = 0L;
                int batched = 0;
                while (rs.next()) {
                    bindRow(rs, md, ps, colCount);
                    ps.addBatch();
                    if (++batched >= BATCH_SIZE) {
                        total += sumBatchResults(ps.executeBatch(), batched);
                        batched = 0;
                    }
                }
                if (batched > 0) {
                    total += sumBatchResults(ps.executeBatch(), batched);
                }
                return total;
            }
        });
    }

    private static long sumBatchResults(final int[] results, final int submitted) {
        long sum = 0L;
        for (final int r : results) {
            // SUCCESS_NO_INFO (-2): driver reports success without a row count; count as 1.
            sum += r == Statement.SUCCESS_NO_INFO ? 1L : Math.max(0, r);
        }
        // If the driver returns an unexpected shape, fall back to the submitted count.
        return sum == 0 ? submitted : sum;
    }

    private static void bindRow(final ResultSet rs, final ResultSetMetaData md,
                                final PreparedStatement ps, final int colCount) throws java.sql.SQLException {
        for (int i = 1; i <= colCount; i++) {
            final int type = md.getColumnType(i);
            switch (type) {
                case Types.TIMESTAMP, Types.TIMESTAMP_WITH_TIMEZONE -> {
                    final Timestamp ts = rs.getTimestamp(i, UTC);
                    if (ts == null) {
                        ps.setNull(i, Types.TIMESTAMP_WITH_TIMEZONE);
                    } else {
                        ps.setTimestamp(i, ts, UTC);
                    }
                }
                case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY, Types.BLOB -> {
                    final byte[] bytes = rs.getBytes(i);
                    if (bytes == null) {
                        ps.setNull(i, Types.VARBINARY);
                    } else {
                        ps.setBytes(i, bytes);
                    }
                }
                case Types.BIT, Types.BOOLEAN -> {
                    final Object v = rs.getObject(i);
                    if (v == null) {
                        ps.setNull(i, Types.BOOLEAN);
                    } else {
                        ps.setBoolean(i, (Boolean) v);
                    }
                }
                default -> ps.setObject(i, rs.getObject(i));
            }
        }
    }

    /**
     * MSSQL has no {@code LIMIT}; rewrite as {@code SELECT TOP N}. The transformation is
     * intentionally narrow: only handles the leading {@code SELECT } the registry emits.
     */
    private static String applyMssqlTopLimit(final String select, final long limit) {
        final String trimmed = select.stripLeading();
        if (!trimmed.regionMatches(true, 0, "SELECT ", 0, 7)) {
            throw new IllegalArgumentException("Cannot apply TOP limit to SQL not starting with SELECT: " + select);
        }
        return "SELECT TOP " + limit + " " + trimmed.substring(7);
    }
}
