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
package org.dependencytrack.support.flyway;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/// @since 5.0.1
public class MigrationExecutor {

    private final Flyway flyway;

    /// @param dataSource         The data source to use.
    /// @param baselineVersion    The baseline schema version.
    /// @param location           Location of the migration files.
    /// @param schemaHistoryTable Name of the schema history table.
    /// @param targetVersion      The schema version to migrate to.
    /// @param outOfOrder         Whether to allow out-of-order execution of migrations.
    /// When `true`, allows patch branches to backport a subset of migrations
    /// from the mainline without blocking the subsequent minor upgrade on validation.
    /// Enable only where backports are anticipated. When disabled, Flyway aborts if it discovers an
    /// unapplied migration with a version lower than the latest in history.
    /// @see [How to fix or avoid ignored migrations in Flyway](https://www.red-gate.com/hub/product-learning/flyway/how-to-fix-or-avoid-ignored-migrations-in-flyway/).
    public MigrationExecutor(
            DataSource dataSource,
            String baselineVersion,
            String location,
            @Nullable String schemaHistoryTable,
            @Nullable String targetVersion,
            boolean outOfOrder) {
        final FluentConfiguration config = Flyway.configure()
                .dataSource(requireNonNull(dataSource, "dataSource must not be null"))
                .baselineVersion(requireNonNull(baselineVersion, "baselineVersion must not be null"))
                .locations(requireNonNull(location, "location must not be null"))
                .baselineOnMigrate(true)
                .cleanDisabled(true)
                .placeholderReplacement(false)
                .outOfOrder(outOfOrder)
                // Acquire the migration lock via a session-level advisory lock instead of a
                // transactional lock. Required for CREATE INDEX CONCURRENTLY to work.
                // https://documentation.red-gate.com/fd/flyway-postgresql-transactional-lock-setting-277579114.html
                //
                // Note that our init task executors also use session-level locks for exactly
                // this reason, and the user-facing contract clearly states that a direct DB
                // connection is required for it (i.e., no PgBouncer in transaction mode).
                .configuration(Map.of("flyway.postgresql.transactional.lock", "false"))
                .loggers("slf4j");
        if (schemaHistoryTable != null) {
            config.table(schemaHistoryTable);
        }
        if (targetVersion != null) {
            config.target(targetVersion);
        }
        this.flyway = config.load();
    }

    public void execute() {
        flyway.migrate();
    }

}
