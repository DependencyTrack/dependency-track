/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack;

import alpine.Config;
import alpine.persistence.PersistenceManagerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.Statement;

public abstract class BaseTest {

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Before
    @After
    @SuppressWarnings("unchecked")
    public void dbReset() throws Exception {
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
