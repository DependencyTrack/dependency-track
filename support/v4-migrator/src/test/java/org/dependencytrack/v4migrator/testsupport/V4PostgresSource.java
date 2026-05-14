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

import org.jdbi.v3.core.Jdbi;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * PostgreSQL Testcontainer pre-shaped with the v4 schema dump.
 */
public final class V4PostgresSource implements AutoCloseable {

    private static final DockerImageName IMAGE = DockerImageName.parse("postgres:14-alpine");

    private final PostgreSQLContainer<?> container;

    public V4PostgresSource() {
        this.container = new PostgreSQLContainer<>(IMAGE)
            .withDatabaseName("dtrackv4")
            .withUsername("dt")
            .withPassword("dt")
            .withInitScript("v4-schema.postgresql.sql");
    }

    public V4PostgresSource start() {
        container.start();
        return this;
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

    public Jdbi jdbi() {
        return Jdbi.create(container.getJdbcUrl(), container.getUsername(), container.getPassword());
    }

    @Override
    public void close() {
        container.stop();
    }
}
