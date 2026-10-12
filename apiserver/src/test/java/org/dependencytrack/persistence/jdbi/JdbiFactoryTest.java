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
package org.dependencytrack.persistence.jdbi;

import alpine.resources.AlpineRequest;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.support.jdbi.exception.UniqueConstraintViolationException;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;

public class JdbiFactoryTest extends PersistenceCapableTest {

    @Test
    public void testGlobalInstance() {
        final Jdbi jdbi = JdbiFactory.createJdbi();

        // Issue a test query to ensure the JDBI instance is functional.
        final Integer queryResult = jdbi.withHandle(
                handle -> handle.createQuery("SELECT 666").mapTo(Integer.class).one());
        assertThat(queryResult).isEqualTo(666);

        // Ensure that the same JDBI instance is returned.
        // Because the underlying PMF did not change, the global JDBI instance must remain untouched.
        assertThat(JdbiFactory.createJdbi()).isEqualTo(jdbi);
    }

    @Test
    public void testGlobalInstanceWithJdoTransaction() {
        qm.runInTransaction(() -> {
            // Create a new project.
            final var project = new Project();
            project.setName("acme-app");
            project.setVersion("1.0.0");
            qm.getPersistenceManager().makePersistent(project);

            // Query for the created project, despite its creation not having been committed yet.
            // Because the global JDBI instance uses a different connection than the QueryManager,
            // it won't be able to see the yet-uncommitted change.
            final Optional<String> projectName = JdbiFactory.createJdbi()
                    .withHandle(handle -> handle.createQuery("SELECT \"NAME\" FROM \"PROJECT\"")
                            .mapTo(String.class)
                            .findFirst());
            assertThat(projectName).isNotPresent();
        });
    }

    @Test
    public void testWithJdbiHandleParticipatesInJdoTransaction() {
        qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

        qm.runInTransaction(() -> {
            final var project = new Project();
            project.setName("acme-app");
            project.setVersion("1.0.0");
            qm.getPersistenceManager().makePersistent(project);

            final Optional<String> projectName = JdbiFactory.withJdbiHandle(qm, handle -> {
                assertThat(handle.getJdbi()).isSameAs(JdbiFactory.createJdbi());
                return handle.createQuery("SELECT \"NAME\" FROM \"PROJECT\"")
                        .mapTo(String.class)
                        .findFirst();
            });
            assertThat(projectName).contains("acme-app");
        });
    }

    @Test
    public void testWithJdbiHandleCarriesApiRequestWithinJdoTransaction() {
        final var request = new AlpineRequest(
                /* principal */ null,
                /* pagination */ null,
                /* filter */ "foo",
                /* orderBy */ null,
                /* orderDirection */ null);

        final var requestQm = new QueryManager(qm.getPersistenceManager(), request);

        requestQm.runInTransaction(() -> {
            final AlpineRequest handleRequest = JdbiFactory.withJdbiHandle(
                    requestQm,
                    handle -> handle.getConfig(ApiRequestConfig.class).apiRequest());
            assertThat(handleRequest).isSameAs(request);
        });
    }

    @Test
    public void testUseJdbiHandleOutsideJdoTransactionRollsBackFailedJdbiTransaction() {
        assertThatThrownBy(() -> JdbiFactory.useJdbiHandle(
                        qm,
                        handle -> handle.useTransaction(_ -> {
                            handle.execute("""
                                INSERT INTO "PROJECT" ("NAME", "VERSION", "UUID")
                                VALUES ('acme-app', '1.0.0', GEN_RANDOM_UUID())
                                """);
                            throw new IllegalStateException("boom");
                        })))
                .isInstanceOf(IllegalStateException.class);

        final int projectCount =
                JdbiFactory.withJdbiHandle(handle -> handle.createQuery("SELECT COUNT(*) FROM \"PROJECT\"")
                        .mapTo(Integer.class)
                        .one());
        assertThat(projectCount).isZero();
    }

    @Test
    public void testUseJdbiHandleTranslatesExceptions() {
        assertThatThrownBy(() -> qm.runInTransaction(() -> JdbiFactory.useJdbiHandle(qm, handle -> {
                    for (int i = 0; i < 2; i++) {
                        handle.execute("""
                            INSERT INTO "PROJECT" ("NAME", "VERSION", "UUID")
                            VALUES ('acme-app', '1.0.0', GEN_RANDOM_UUID())
                            """);
                    }
                })))
                .isInstanceOf(UniqueConstraintViolationException.class);
    }

    @Test
    public void testWithJdbiHandleRejectsNestingInOtherHandle() {
        assertThatThrownBy(() -> JdbiFactory.useJdbiHandle(
                        _ -> qm.runInTransaction(() -> JdbiFactory.useJdbiHandle(qm, _ -> {}))))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void testWithJdbiHandleRejectsNesting() {
        try (final var otherQm = new QueryManager()) {
            assertThatThrownBy(() -> qm.runInTransaction(() -> JdbiFactory.useJdbiHandle(
                            qm, _ -> otherQm.runInTransaction(() -> JdbiFactory.useJdbiHandle(otherQm, _ -> {})))))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    public void testUseJdbiHandleIsRolledBackWithJdoTransaction() {
        assertThatThrownBy(() -> qm.runInTransaction(() -> {
                    JdbiFactory.useJdbiHandle(qm, handle -> handle.execute("""
                        INSERT INTO "PROJECT" ("NAME", "VERSION", "UUID")
                        VALUES ('acme-app', '1.0.0', GEN_RANDOM_UUID())
                        """));
                    throw new IllegalStateException("boom");
                }))
                .isInstanceOf(IllegalStateException.class);

        final int projectCount =
                JdbiFactory.withJdbiHandle(handle -> handle.createQuery("SELECT COUNT(*) FROM \"PROJECT\"")
                        .mapTo(Integer.class)
                        .one());
        assertThat(projectCount).isZero();
    }

    @Test
    public void testStatementsCarryQueryTimeoutDefault() throws SQLException {
        final int queryTimeout = JdbiFactory.<Integer, SQLException>withJdbiHandle(handle -> {
            try (Statement statement = handle.getConnection().createStatement()) {
                return statement.getQueryTimeout();
            }
        });

        assertThat(queryTimeout).isEqualTo(60);
    }
}
