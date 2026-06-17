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
import org.postgresql.copy.CopyManager;
import org.postgresql.core.BaseConnection;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.sql.Connection;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Source extractor for PostgreSQL v4. Uses {@code COPY ... TO STDOUT BINARY} on the source
 * piped directly into {@code COPY ... FROM STDIN BINARY} on the target.
 */
final class PostgresExtractor implements SourceExtractor {

    private final SourceOptions source;
    private final String sourceSchema;

    PostgresExtractor(final SourceOptions source, final String sourceSchema) {
        this.source = source;
        this.sourceSchema = sourceSchema;
    }

    @Override
    public long extract(final TableMigration table, final String stagingSchema,
                        final Jdbi target, final long sampleLimit) throws Exception {
        try (Connection src = Connections.openSource(source)) {
            src.setAutoCommit(false);
            return streamCopy(src, table, stagingSchema, target, sampleLimit);
        }
    }

    private long streamCopy(final Connection src, final TableMigration table,
                            final String stagingSchema, final Jdbi target,
                            final long sampleLimit) throws Exception {
        final String renderedSelect = table.extractSelect().formatted(sourceSchema);
        final String selectSql = sampleLimit == Long.MAX_VALUE
            ? renderedSelect
            : renderedSelect + " LIMIT " + sampleLimit;
        final String srcCopySql = "COPY (" + selectSql + ") TO STDOUT WITH (FORMAT BINARY)";
        final String quotedCols = table.extractColumns().stream()
            .map(c -> "\"" + c + "\"")
            .reduce((a, b) -> a + ", " + b)
            .orElseThrow();
        final String tgtCopySql = "COPY \"%s\".src_%s (%s) FROM STDIN WITH (FORMAT BINARY)"
            .formatted(stagingSchema, table.name(), quotedCols);

        final PipedInputStream pipeIn = new PipedInputStream(1 << 16);
        final PipedOutputStream pipeOut = new PipedOutputStream(pipeIn);

        final ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            final Future<Long> writer = pool.submit((Callable<Long>) () -> {
                final BaseConnection pgSrc = src.unwrap(BaseConnection.class);
                try (pipeOut) {
                    return new CopyManager(pgSrc).copyOut(srcCopySql, pipeOut);
                }
            });
            final Future<Long> reader = pool.submit((Callable<Long>) () -> target.withHandle(h -> {
                final BaseConnection pgTgt = h.getConnection().unwrap(BaseConnection.class);
                return new CopyManager(pgTgt).copyIn(tgtCopySql, pipeIn);
            }));
            // Await reader first: if the reader fails (e.g. target-side error), the writer
            // would otherwise block forever filling the pipe nobody is draining. On reader
            // failure we close pipeIn so copyOut errors out and the writer thread terminates.
            try {
                return reader.get();
            } catch (final ExecutionException readerEe) {
                try {
                    pipeIn.close();
                } catch (final Exception ignore) {
                    // best-effort
                }
                final Throwable cause = readerEe.getCause();
                if (cause instanceof Exception ex) {
                    throw ex;
                }
                throw new RuntimeException(cause);
            } finally {
                try {
                    writer.get();
                } catch (final Exception ignore) {
                    // writer outcome is irrelevant once the reader has resolved
                }
            }
        } finally {
            pool.shutdown();
            if (!pool.awaitTermination(30, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        }
    }
}
