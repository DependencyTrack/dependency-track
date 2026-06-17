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
package org.dependencytrack.support.datanucleus;

import org.datanucleus.PropertyNames;
import org.dependencytrack.support.datanucleus.method.JsonbContainsMethod;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import java.net.URL;
import java.util.Map;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

public abstract class AbstractTest {

    private static PostgreSQLContainer postgresContainer;
    private static PersistenceManagerFactory pmf;
    protected PersistenceManager pm;

    @BeforeAll
    static void beforeAll() {
        postgresContainer = new PostgreSQLContainer("postgres:14-alpine")
                .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));
        postgresContainer.start();

        pmf = createPmf(postgresContainer);
    }

    @BeforeEach
    void beforeEach() {
        pm = pmf.getPersistenceManager();
    }

    @AfterEach
    void afterEach() {
        pm.newQuery(Query.SQL, "TRUNCATE TABLE \"PERSON\"").execute();

        if (pm != null) {
            pm.close();
        }
    }

    @AfterAll
    static void afterAll() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
        if (pmf != null) {
            pmf.close();
        }
    }

    private static PersistenceManagerFactory createPmf(final PostgreSQLContainer postgresContainer) {
        final URL schemaUrl = JsonbContainsMethod.class.getResource("/schema.sql");
        assertThat(schemaUrl).isNotNull();

        return JDOHelper.getPersistenceManagerFactory(
                Map.ofEntries(
                        entry(PropertyNames.PROPERTY_PERSISTENCE_UNIT_NAME, "test"),
                        entry(PropertyNames.PROPERTY_SCHEMA_GENERATE_DATABASE_MODE, "drop-and-create"),
                        entry(PropertyNames.PROPERTY_SCHEMA_GENERATE_DATABASE_CREATE_SCRIPT, schemaUrl.toString()),
                        entry(PropertyNames.PROPERTY_CONNECTION_URL, postgresContainer.getJdbcUrl()),
                        entry(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, postgresContainer.getDriverClassName()),
                        entry(PropertyNames.PROPERTY_CONNECTION_USER_NAME, postgresContainer.getUsername()),
                        entry(PropertyNames.PROPERTY_CONNECTION_PASSWORD, postgresContainer.getPassword()),
                        entry(PropertyNames.PROPERTY_QUERY_SQL_ALLOWALL, "true")),
                "test");
    }

}
