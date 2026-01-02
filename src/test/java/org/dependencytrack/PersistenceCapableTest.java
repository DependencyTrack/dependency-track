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

import alpine.Config;
import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import javax.jdo.Query;
import java.time.Duration;

public abstract class PersistenceCapableTest {

    protected QueryManager qm;

    @BeforeAll
    static void init() {
        Config.enableUnitTests();

        // ensure nothing is left open so the database is properly cleaned up between tests
        System.setProperty(Config.AlpineKey.DATABASE_POOL_ENABLED.getPropertyName(), "false");
    }

    @BeforeEach
    final void initQueryManager() throws InterruptedException {
        this.qm = new QueryManager();
        for (int i = 0; i < 5 && qm.getPersistenceManager().isClosed(); ++i) {
            Thread.sleep(Duration.ofSeconds(1));
        }
    }

    @AfterEach
    final void tearDownQueryManager() {
        // PersistenceManager will refuse to close when there's an active transaction
        // that was neither committed nor rolled back. Unfortunately some areas of the
        // code base can leave such a broken state behind if they run into unexpected
        // errors. See: https://github.com/DependencyTrack/dependency-track/issues/2677
        if (!qm.getPersistenceManager().isClosed()
                && qm.getPersistenceManager().currentTransaction().isActive()) {
            qm.getPersistenceManager().currentTransaction().rollback();
        }

        // Add a small delay to allow pending operations to complete
        // FIXME This is a very dumb "solution" and probably only reduces the probability of any connection errors to
        //       occur. The underlying issue (it seems) is that some resource is not closed properly in time. The error
        //       is non-deterministic.
        try {
            Thread.sleep(Duration.ofMillis(100));
        } catch (InterruptedException e) {
            // Ignore
        }

        try {
            // Make sure the in-memory H2 database is closed before the next test is run.
            qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_QUERY_SQL_ALLOWALL, "true");
            try(final var q = qm.getPersistenceManager().newQuery(Query.SQL, "SHUTDOWN IMMEDIATELY")) {
                q.execute();
            }
        } catch (Exception e) {
            // ignored, DB already closed.
        }

        qm.close();
        qm = null;

        try {
            PersistenceManagerFactory.tearDown();
        } catch (NullPointerException e) {
            // ignored, may happen if there is no transaction left
        }
    }

}
