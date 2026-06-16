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
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jspecify.annotations.NullMarked;
import org.postgresql.ds.PGSimpleDataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

@NullMarked
public final class TestDatabaseEventListener implements org.dependencytrack.testing.database.TestDatabaseEventListener {

    @Override
    public void onDatabaseInitialized(String jdbcUrl, String username, String password) {
        MemoryConfigSource.setProperty("dt.datasource.url", jdbcUrl);
        MemoryConfigSource.setProperty("dt.datasource.username", username);
        MemoryConfigSource.setProperty("dt.datasource.password", password);

        // Mirror DatabasePartitionMaintenanceInitTask: production runs this on startup,
        // and tests have no equivalent init chain. Without it, inserts dated to today
        // hit "no partition" because the schema baseline carries no metric partitions.
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(jdbcUrl);
        dataSource.setUser(username);
        dataSource.setPassword(password);

        final var jdbi = JdbiFactory.createLocalJdbi(dataSource);
        jdbi.useTransaction(handle -> handle.attach(MetricsDao.class).createMetricsPartitions());

        new PersistenceManagerFactory().contextInitialized(null);
    }

    @Override
    public void onTablesTruncated() {
        try (final Connection connection = DataSourceRegistry.getInstance().getDefault().getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$
                    DECLARE
                      partition_name TEXT;
                      today_partition_pattern TEXT := FORMAT('^(PROJECT|DEPENDENCY)METRICS_%s', TO_CHAR(CURRENT_DATE, 'YYYYMMDD'));
                      tomorrow_partition_pattern TEXT := FORMAT('^(PROJECT|DEPENDENCY)METRICS_%s', TO_CHAR(CURRENT_DATE + 1, 'YYYYMMDD'));
                    BEGIN
                      FOR partition_name IN
                        SELECT tablename
                          FROM pg_tables
                         WHERE tablename ~ '^(PROJECT|DEPENDENCY)METRICS_[0-9]{8}$'
                           AND tablename !~ today_partition_pattern
                           AND tablename !~ tomorrow_partition_pattern
                      LOOP
                        EXECUTE FORMAT('DROP TABLE %I', partition_name);
                      END LOOP;
                    END $$;
                    """);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to drop stale metrics partitions", e);
        }
    }

}
