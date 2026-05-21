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

import alpine.server.auth.PasswordService;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.sql.Connection;
import java.sql.Statement;

public abstract class PersistenceCapableTest {

    protected QueryManager qm;

    protected static final String TEST_PASSWORD_HASH = new String(
            PasswordService.createHash("testuser".toCharArray()));

    @BeforeAll
    public static void init() {
        TestDatabaseManager.initialize();
    }

    @BeforeEach
    public void before() throws Exception {
        truncateTables();

        qm = new QueryManager();
    }

    @AfterEach
    public void after() {
        // PersistenceManager will refuse to close when there's an active transaction
        // that was neither committed nor rolled back. Unfortunately some areas of the
        // code base can leave such a broken state behind if they run into unexpected
        // errors. See: https://github.com/DependencyTrack/dependency-track/issues/2677
        if (!qm.getPersistenceManager().isClosed()
                && qm.getPersistenceManager().currentTransaction().isActive()) {
            qm.getPersistenceManager().currentTransaction().rollback();
        }

        qm.close();
    }

    protected static void truncateTables() throws Exception {
        try (final Connection connection = DataSourceRegistry.getInstance().getDefault().getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$ DECLARE
                        table_list TEXT;
                    BEGIN
                        SELECT STRING_AGG(QUOTE_IDENT(tablename), ', ')
                          INTO table_list
                          FROM pg_tables
                         WHERE schemaname = CURRENT_SCHEMA()
                           AND tablename != 'databasechangelog'
                           AND tablename !~ '^.+schema_history$';
                        IF table_list IS NOT NULL THEN
                            EXECUTE 'TRUNCATE TABLE ' || table_list || ' CASCADE';
                        END IF;
                    END $$;
                    """);

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
        }
    }

}
