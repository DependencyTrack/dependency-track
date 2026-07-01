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
package org.dependencytrack.testing.database;

import com.github.dockerjava.api.command.InspectContainerResponse;
import org.dependencytrack.migration.MigrationExecutor;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

/// A PostgreSQL testcontainer carrying the full Dependency-Track schema.
///
/// The container is configured for reuse across JVMs and modules.
/// Its configuration must remain identical for every consumer,
/// otherwise Testcontainers computes a different reuse hash and starts a separate container,
/// defeating the purpose. **Do not add module-specific labels or settings here**!
///
/// Migrations run once on the `dtrack` template database when the container is
/// first started. When the container is reused, migration is skipped.
///
/// @since 5.1.0
public final class PostgresTestContainer extends PostgreSQLContainer {

    @SuppressWarnings("resource")
    public PostgresTestContainer() {
        super(DockerImageName.parse("postgres:14-alpine"));
        withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off");
        withUsername("dtrack");
        withPassword("dtrack");
        withDatabaseName("dtrack");
        withUrlParam("reWriteBatchedInserts", "true");
        withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));
        withLabel("org.dependencytrack.test-database", "true");

        // NB: Container reuse won't be active unless either:
        //  - The environment variable TESTCONTAINERS_REUSE_ENABLE=true is set
        //  - testcontainers.reuse.enable=true is set in ~/.testcontainers.properties
        withReuse(true);
    }

    @Override
    protected void containerIsStarted(InspectContainerResponse containerInfo, boolean reused) {
        super.containerIsStarted(containerInfo, reused);

        if (reused) {
            logger().debug("Reusing container; Migration not necessary");
            return;
        }

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(getJdbcUrl());
        dataSource.setUser(getUsername());
        dataSource.setPassword(getPassword());

        new MigrationExecutor(dataSource).execute();
    }

}
