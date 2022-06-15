package org.dependencytrack.upgrade.v460;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;

public class v460Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v460Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.6.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        // Fixes https://github.com/DependencyTrack/dependency-track/issues/1661
        // The JDBC type "CLOB" is mapped to the type CLOB for H2, MEDIUMTEXT for MySQL, and TEXT for PostgreSQL and SQL Server.
        // - https://github.com/datanucleus/datanucleus-rdbms/blob/datanucleus-rdbms-5.2.11/src/main/java/org/datanucleus/store/rdbms/adapter/H2Adapter.java#L484
        // - https://github.com/datanucleus/datanucleus-rdbms/blob/datanucleus-rdbms-5.2.11/src/main/java/org/datanucleus/store/rdbms/adapter/MySQLAdapter.java#L185-L186
        // - https://github.com/datanucleus/datanucleus-rdbms/blob/datanucleus-rdbms-5.2.11/src/main/java/org/datanucleus/store/rdbms/adapter/PostgreSQLAdapter.java#L144
        // - https://github.com/datanucleus/datanucleus-rdbms/blob/datanucleus-rdbms-5.2.11/src/main/java/org/datanucleus/store/rdbms/adapter/SQLServerAdapter.java#L168-L169
        LOGGER.info("Changing JDBC type of \"ANALYSIS\".\"DETAILS\" from VARCHAR to CLOB");
        if (DbUtil.isH2()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"DETAILS_V46\" CLOB");
        } else if (DbUtil.isMysql()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"DETAILS_V46\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"DETAILS_V46\" TEXT");
        }
        DbUtil.executeUpdate(connection, "UPDATE \"ANALYSIS\" SET \"DETAILS_V46\" = \"DETAILS\"");
        DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" DROP COLUMN \"DETAILS\"");
        DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" RENAME COLUMN \"DETAILS_V46\" TO \"DETAILS\"");
    }
}
