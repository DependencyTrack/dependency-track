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
package org.dependencytrack;

import alpine.server.persistence.PersistenceManagerFactory;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantLock;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Manages a shared PostgreSQL testcontainer and per-JVM test database.
 * <p>
 * The container runs migrations on a template database. Each JVM gets its own
 * database created via {@code CREATE DATABASE ... TEMPLATE}, providing isolation
 * without repeating migrations. The PID of the JVM is used as the database name suffix
 * to guarantee uniqueness.
 */
public final class TestDatabaseManager {

    private static final ReentrantLock LOCK = new ReentrantLock();
    private static boolean initialized;

    private TestDatabaseManager() {
    }

    public static void initialize() {
        if (initialized) {
            return;
        }

        LOCK.lock();
        try {
            if (initialized) {
                return;
            }

            // Serialize container startup across JVM instances using a file lock.
            // Without this, concurrent forks that don't find a reusable container
            // each create their own, defeating the purpose of testcontainer reuse
            // and template databases.
            final var container = new PostgresTestContainer();
            final long pid = ProcessHandle.current().pid();
            final String dbName = "dtrack_" + pid;

            final Path lockFile = Path.of(
                    System.getProperty("java.io.tmpdir"),
                    "apiserver-postgres-testcontainer.lock");
            try (final var channel = FileChannel.open(lockFile, CREATE, WRITE);
                 var _ = channel.lock()) {
                container.start();
                dropStaleDatabases(container, pid);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to acquire container lock", e);
            }

            // NB: Must connect to the "postgres" DB to create the test DB.
            // Cannot connect to "dtrack" because CREATE DATABASE requires
            // no active connections to the template.
            try (final Connection connection = DriverManager.getConnection(
                    container.getJdbcUrl().replace("/dtrack?", "/postgres?"),
                    container.getUsername(),
                    container.getPassword());
                 final Statement statement = connection.createStatement()) {
                statement.execute("CREATE DATABASE %s TEMPLATE dtrack".formatted(dbName));
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to create test database " + dbName, e);
            }

            MemoryConfigSource.setProperty(
                    "dt.datasource.url",
                    container.getJdbcUrl().replace("/dtrack?", "/%s?".formatted(dbName)));
            MemoryConfigSource.setProperty("dt.datasource.username", container.getUsername());
            MemoryConfigSource.setProperty("dt.datasource.password", container.getPassword());

            new PersistenceManagerFactory().contextInitialized(null);

            initialized = true;
        } finally {
            LOCK.unlock();
        }
    }

    private static void dropStaleDatabases(PostgresTestContainer container, long pid) {
        try (final Connection connection = DriverManager.getConnection(
                container.getJdbcUrl().replace("/dtrack?", "/postgres?"),
                container.getUsername(),
                container.getPassword());
             final Statement statement = connection.createStatement()) {
            final var staleDatabases = new ArrayList<String>();
            try (final ResultSet rs = statement.executeQuery("""
                    SELECT datname
                      FROM pg_database
                     WHERE datname ~ '^dtrack_[0-9]+$'
                    """)) {
                while (rs.next()) {
                    final String existingDb = rs.getString(1);
                    final String pidStr = existingDb.substring("dtrack_".length());
                    try {
                        final long existingPid = Long.parseLong(pidStr);
                        if (ProcessHandle.of(existingPid).isEmpty() || existingPid == pid) {
                            staleDatabases.add(existingDb);
                        }
                    } catch (NumberFormatException _) {
                    }
                }
            }

            for (final String db : staleDatabases) {
                statement.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)".formatted(db));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to drop stale databases", e);
        }
    }

}
