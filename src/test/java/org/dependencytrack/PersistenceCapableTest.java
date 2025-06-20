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
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public abstract class PersistenceCapableTest {

    protected QueryManager qm;

    @BeforeAll
    static void init() {
        Config.enableUnitTests();

        // ensure nothing is left open so the database is properly cleaned up between tests
        System.setProperty(Config.AlpineKey.DATABASE_POOL_TX_MAX_LIFETIME.getPropertyName(), "0");
        System.setProperty(Config.AlpineKey.DATABASE_POOL_NONTX_MAX_LIFETIME.getPropertyName(), "0");
        System.setProperty(Config.AlpineKey.DATABASE_POOL_TX_IDLE_TIMEOUT.getPropertyName(), "0");
        System.setProperty(Config.AlpineKey.DATABASE_POOL_NONTX_IDLE_TIMEOUT.getPropertyName(), "0");
    }

    @BeforeEach
    final void initQueryManager() {
        this.qm = new QueryManager();
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

        PersistenceManagerFactory.tearDown();
    }

}
