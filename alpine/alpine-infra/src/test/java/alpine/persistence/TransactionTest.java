/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.persistence;

import alpine.model.ManagedUser;
import alpine.model.Team;
import alpine.persistence.Transaction.Isolation;
import alpine.persistence.Transaction.Options;
import alpine.persistence.Transaction.Propagation;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.JDOHelper;

import static alpine.persistence.Transaction.defaultOptions;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TransactionTest {

    private JDOPersistenceManagerFactory pmf;
    private AlpineQueryManager qm;

    @BeforeEach
    public void setUp() {
        pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(JdoProperties.unit(), "Alpine");
        qm = new AlpineQueryManager(pmf.getPersistenceManager());
    }

    @AfterEach
    public void tearDown() {
        if (qm != null) {
            qm.close();
        }

        if (pmf != null) {
            pmf.close();
        }
    }

    @Test
    public void testRetainValues() {
        final Team team = qm.callInTransaction(() -> qm.createTeam("foo"));
        qm.close(); // Close PM to prevent lazy loading of values when getters are called.

        // Ensure the values assigned during the transaction are present.
        assertThat(team.getName()).isEqualTo("foo");
        assertEquals(0, team.getApiKeys().size());
    }

    @Test
    public void testTransactionRollback() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> qm.runInTransaction(() -> {
                    final ManagedUser user = qm.createManagedUser("username", "passwordHash");
                    final Team team = qm.createTeam("foo");
                    final boolean added = qm.addUserToTeam(user, team);
                    assertThat(added).isTrue();

                    throw new IllegalStateException();
                }));

        // Changes made in the transaction must have been rolled back.
        assertThat(qm.getManagedUser("username")).isNull();
        assertThat(qm.getTeam("foo")).isNull();
    }

    @Test
    public void testNestedTransactionRollback() {
        qm.runInTransaction(() -> {
            final ManagedUser userA = qm.createManagedUser("usernameA", "passwordHash");
            final ManagedUser userB = qm.createManagedUser("usernameB", "passwordHash");
            final Team team = qm.createTeam("foo");

            final boolean addedUserA = qm.addUserToTeam(userA, team);
            assertThat(addedUserA).isTrue();

            // Run the addition of userB to the team in a nested transaction.
            // The transaction should join the currently active one.
            // Throw an exception at the end. The exception must not cause
            // the transaction to be rolled back.
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> qm.runInTransaction(() -> {
                        final boolean addedUserB = qm.addUserToTeam(userB, team);
                        assertThat(addedUserB).isTrue();

                        throw new IllegalStateException();
                    }));
        });

        final ManagedUser userA = qm.getManagedUser("usernameA");
        assertThat(userA).isNotNull();
        assertThat(userA.getTeams()).hasSize(1);

        final ManagedUser userB = qm.getManagedUser("usernameB");
        assertThat(userB).isNotNull();
        assertThat(userB.getTeams()).hasSize(1);
    }

    @Test
    public void testNestedTransactionWithRequiresNewPropagation() {
        qm.runInTransaction(() ->
                assertThatExceptionOfType(IllegalStateException.class)
                        .isThrownBy(() -> {
                            final Options trxOptions = defaultOptions().withPropagation(Propagation.REQUIRES_NEW);
                            qm.runInTransaction(trxOptions, () -> {
                            });
                        })
                        .withMessage("Propagation is set to REQUIRES_NEW, but a transaction is already active")
        );
    }

    @Test
    public void testNestedTransactionWithIsolationMismatch() {
        qm.runInTransaction(() ->
                assertThatExceptionOfType(IllegalStateException.class)
                        .isThrownBy(() -> {
                            final Options trxOptions = defaultOptions().withIsolation(Isolation.SERIALIZABLE);
                            qm.runInTransaction(trxOptions, () -> {
                            });
                        })
                        .withMessage("""
                                Requested isolation is SERIALIZABLE, but transaction is already \
                                active with isolation READ_COMMITTED""")
        );
    }

    @Test
    public void testNestedTransactionWithSerializeReadMismatch() {
        qm.runInTransaction(() ->
                assertThatExceptionOfType(IllegalStateException.class)
                        .isThrownBy(() -> {
                            final Options trxOptions = defaultOptions().withSerializeRead(true);
                            qm.runInTransaction(trxOptions, () -> {
                            });
                        })
                        .withMessage("""
                                Requested serializeRead=true, but transaction is already \
                                active with serializeRead=false""")
        );
    }

    @Test
    public void testIsolationRestore() {
        final Options trxOptions = defaultOptions().withIsolation(Isolation.SERIALIZABLE);
        qm.runInTransaction(trxOptions, () -> {
        });

        assertThat(qm.getPersistenceManager().currentTransaction().getIsolationLevel()).isEqualTo("read-committed");
    }

    @Test
    public void testSerializableReadRestore() {
        final Options trxOptions = defaultOptions().withSerializeRead(true);
        qm.runInTransaction(trxOptions, () -> {
        });

        assertThat(qm.getPersistenceManager().currentTransaction().getSerializeRead()).isFalse();
    }

}
