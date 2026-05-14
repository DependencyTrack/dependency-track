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

import org.dependencytrack.migration.MigrationExecutor;
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.jdbi.v3.core.Jdbi;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;

/**
 * Wraps a PostgreSQL Testcontainer with the v5 schema already applied via Flyway.
 */
public final class V5TargetContainer implements AutoCloseable {

    private static final DockerImageName IMAGE = DockerImageName.parse("postgres:14-alpine");

    private final PostgreSQLContainer<?> container;

    public V5TargetContainer() {
        this.container = new PostgreSQLContainer<>(IMAGE)
            .withDatabaseName("dtrackv5")
            .withUsername("dt")
            .withPassword("dt");
    }

    public V5TargetContainer start() {
        container.start();
        new MigrationExecutor(dataSource(), Preflight.EXPECTED_FLYWAY_HEAD).execute();
        seedPermissions();
        return this;
    }

    /**
     * Mimic the v5 apiserver's {@code DatabaseSeedingInitTask}, which populates {@code PERMISSION}
     * on first boot. The migrator's preflight refuses to run against an empty PERMISSION table,
     * so tests must reproduce that initial state. A minimal seed is enough for preflight.
     */
    private void seedPermissions() {
        jdbi().useHandle(h -> h.execute("""
            INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION")
            VALUES ('VIEW_PORTFOLIO', 'View projects, components, vulnerabilities')
            ON CONFLICT ("NAME") DO NOTHING
            """));
    }

    public String jdbcUrl() {
        return container.getJdbcUrl();
    }

    public String username() {
        return container.getUsername();
    }

    public String password() {
        return container.getPassword();
    }

    public DataSource dataSource() {
        return new org.postgresql.ds.PGSimpleDataSource() {{
            setUrl(container.getJdbcUrl());
            setUser(container.getUsername());
            setPassword(container.getPassword());
        }};
    }

    public Jdbi jdbi() {
        return Jdbi.create(container.getJdbcUrl(), container.getUsername(), container.getPassword());
    }

    @Override
    public void close() {
        container.stop();
    }
}
