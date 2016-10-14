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
package org.owasp.dependencytrack.persistence;

import org.owasp.dependencytrack.Config;
import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Properties;

public class LocalPersistenceManagerFactory implements ServletContextListener {

    // The following properties are used for unit tests
    private static final Properties jdoOverrides;
    static {
        jdoOverrides = new Properties();
        jdoOverrides.put("javax.jdo.option.ConnectionURL", "jdbc:h2:mem:dependency-track");
        jdoOverrides.put("javax.jdo.option.ConnectionDriverName", "org.h2.Driver");
        jdoOverrides.put("javax.jdo.option.ConnectionUserName", "sa");
        jdoOverrides.put("javax.jdo.option.ConnectionPassword", "");
        jdoOverrides.put("javax.jdo.option.Mapping", "h2");
        jdoOverrides.put("datanucleus.connectionPoolingType", "DBCP");
        jdoOverrides.put("datanucleus.schema.autoCreateSchema", "true");
        jdoOverrides.put("datanucleus.schema.autoCreateTables", "true");
        jdoOverrides.put("datanucleus.schema.autoCreateColumns", "true");
        jdoOverrides.put("datanucleus.schema.autoCreateConstraints", "true");
        jdoOverrides.put("datanucleus.query.jdoql.allowAll", "true");
        jdoOverrides.put("datanucleus.NontransactionalRead", "true");
        jdoOverrides.put("datanucleus.NontransactionalWrite", "true");
        jdoOverrides.put("datanucleus.nontx.atomic", "true");
    }

    private static PersistenceManagerFactory pmf;

    public void contextInitialized(ServletContextEvent event) {
        pmf = JDOHelper.getPersistenceManagerFactory("Dependency-Track");
    }

    public void contextDestroyed(ServletContextEvent event) {
        pmf.close();
    }

    public static PersistenceManager createPersistenceManager() {
        if (Config.isUnitTestsEnabled()) {
            pmf = JDOHelper.getPersistenceManagerFactory(jdoOverrides, "Dependency-Track");
        }
        if (pmf == null) {
            throw new IllegalStateException("Context is not initialized yet.");
        }
        return pmf.getPersistenceManager();
    }

}