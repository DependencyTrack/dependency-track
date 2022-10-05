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
package org.dependencytrack.upgrade.v460;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;

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
        if (DbUtil.isMssql()) { // Really, Microsoft? You're being weird.
            DbUtil.executeUpdate(connection, "EXEC sp_rename 'ANALYSIS.DETAILS_V46', 'DETAILS', 'COLUMN'");
        } else if (DbUtil.isMysql()) { // MySQL < 8.0 does not support RENAME COLUMN and needs a special treatment.
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" CHANGE \"DETAILS_V46\" \"DETAILS\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" RENAME COLUMN \"DETAILS_V46\" TO \"DETAILS\"");
        }

        LOGGER.info("Updating Package URLs of PHP Packages for GHSA Vulnerabilities");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery("""
                    SELECT "ID", "PURL_NAME"
                    FROM "VULNERABLESOFTWARE"
                    WHERE "PURL_TYPE" = 'composer'
                        AND "PURL_NAMESPACE" IS NULL
                        AND "PURL_NAME" LIKE '%/%'
                    """);
            while (rs.next()) {
                final String purlName = rs.getString(2);
                final String[] purlParts = purlName.split("/");

                final String namespace = String.join("/", Arrays.copyOfRange(purlParts, 0, purlParts.length - 1));

                final PreparedStatement ps = connection.prepareStatement("""
                        UPDATE "VULNERABLESOFTWARE" SET "PURL_NAMESPACE" = ?, "PURL_NAME" = ? WHERE "ID" = ?
                        """);
                ps.setString(1, namespace);
                ps.setString(2, purlParts[purlParts.length - 1]);
                ps.setLong(3, rs.getLong(1));
                ps.executeUpdate();
            }
        }
    }
}
