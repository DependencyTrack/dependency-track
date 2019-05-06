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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack;

import alpine.Config;
import alpine.persistence.PersistenceManagerFactory;
import org.dependencytrack.persistence.QueryManager;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.Statement;

public abstract class PersistenceCapableTest {

    protected QueryManager qm;

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Before
    public void before() throws Exception {
        dbReset();
        this.qm = new QueryManager();
    }

    @After
    public void after() throws Exception {
        dbReset();
        this.qm.close();
    }

    @SuppressWarnings("unchecked")
    static void dbReset() throws Exception {
        PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager();
        JDOConnection jdoConnection = pm.getDataStoreConnection();
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = (Connection)jdoConnection.getNativeConnection();
            stmt = conn.createStatement();
            stmt.executeUpdate("DROP ALL OBJECTS DELETE FILES");
        } finally {
            if (conn != null) {
                conn.close();
            }
            if (stmt != null) {
                stmt.close();
            }
        }
        pm.close();
    }
}
