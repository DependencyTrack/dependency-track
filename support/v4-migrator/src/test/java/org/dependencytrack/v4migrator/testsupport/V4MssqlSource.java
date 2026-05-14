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
package org.dependencytrack.v4migrator.testsupport;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.MSSQLServerContainer;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.function.Consumer;

/**
 * Microsoft SQL Server Testcontainer pre-shaped with the v4 schema dump.
 * The dump is an SSDT/SQLCMD deployment script (with {@code GO} batches and {@code :setvar}
 * directives), so it is applied via {@code sqlcmd} inside the container rather than JDBC.
 */
public final class V4MssqlSource implements AutoCloseable {

    private static final DockerImageName IMAGE =
        DockerImageName.parse("mcr.microsoft.com/mssql/server:2022-latest")
            .asCompatibleSubstituteFor("mcr.microsoft.com/mssql/server");

    private static final String SCHEMA_RESOURCE = "/v4-schema.mssql.sql";
    private static final String DB_NAME = "dtrack_empty";

    private final MSSQLServerContainer<?> container;

    public V4MssqlSource() {
        this.container = new MSSQLServerContainer<>(IMAGE).acceptLicense();
    }

    public V4MssqlSource start() {
        container.start();
        applyV4Schema();
        return this;
    }

    private void applyV4Schema() {
        final byte[] script;
        try (InputStream in = getClass().getResourceAsStream(SCHEMA_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Schema resource missing: " + SCHEMA_RESOURCE);
            }
            script = in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + SCHEMA_RESOURCE, e);
        }
        container.copyFileToContainer(Transferable.of(script), "/tmp/v4-schema.sql");
        final ExecResult result;
        try {
            result = container.execInContainer(
                "/opt/mssql-tools18/bin/sqlcmd",
                "-S", "localhost",
                "-U", container.getUsername(),
                "-P", container.getPassword(),
                "-C",
                "-b",
                "-i", "/tmp/v4-schema.sql"
            );
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException("sqlcmd invocation failed", e);
        }
        if (result.getExitCode() != 0) {
            throw new IllegalStateException("sqlcmd exited " + result.getExitCode()
                + "\nstdout:\n" + result.getStdout()
                + "\nstderr:\n" + result.getStderr());
        }
    }

    public String jdbcUrl() {
        return container.getJdbcUrl() + ";databaseName=" + DB_NAME + ";loginTimeout=30";
    }

    public String username() {
        return container.getUsername();
    }

    public String password() {
        return container.getPassword();
    }

    public Jdbi jdbi() {
        return Jdbi.create(jdbcUrl(), container.getUsername(), container.getPassword());
    }

    /**
     * Runs {@code block} with {@code IDENTITY_INSERT [table] ON} for the duration of one
     * connection. Required when seeding rows with explicit {@code ID} values, since the
     * v4 schema declares ID columns as {@code IDENTITY}. The MSSQL JDBC driver runs
     * prepared statements via {@code sp_executesql}, so the {@code SET} must be issued
     * through a direct {@link Statement} to leak into subsequent statements on the same
     * connection.
     */
    public void withIdentityInsert(String table, Consumer<Handle> block) {
        jdbi().useHandle(h -> {
            toggleIdentityInsert(h, table, true);
            try {
                block.accept(h);
            } finally {
                toggleIdentityInsert(h, table, false);
            }
        });
    }

    private static void toggleIdentityInsert(Handle h, String table, boolean on) {
        try (Statement s = h.getConnection().createStatement()) {
            s.execute("SET IDENTITY_INSERT [" + table + "] " + (on ? "ON" : "OFF"));
        } catch (SQLException e) {
            throw new IllegalStateException("SET IDENTITY_INSERT failed for " + table, e);
        }
    }

    @Override
    public void close() {
        container.stop();
    }
}
