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
package org.dependencytrack.upgrade.v480;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;

import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_USERNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_PASSWORD;

public class v480Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v480Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.8.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        changeJdbcTypeOfComponentAuthorColumn(connection);
        setJiraPropertyValuesFromJiraToIntegrationGroup(qm, connection);
    }

    private void changeJdbcTypeOfComponentAuthorColumn(Connection connection) throws Exception {
        // Fixes https://github.com/DependencyTrack/dependency-track/issues/2488
        // The JDBC type "CLOB" is mapped to the type CLOB for H2, MEDIUMTEXT for MySQL, and TEXT for PostgreSQL and SQL Server.
        LOGGER.info("Changing JDBC type of \"COMPONENT\".\"AUTHOR\" from VARCHAR to CLOB");
        if (DbUtil.isH2()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" ADD \"AUTHOR_V48\" CLOB");
        } else if (DbUtil.isMysql()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" ADD \"AUTHOR_V48\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" ADD \"AUTHOR_V48\" TEXT");
        }
        DbUtil.executeUpdate(connection, "UPDATE \"COMPONENT\" SET \"AUTHOR_V48\" = \"AUTHOR\"");
        DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" DROP COLUMN \"AUTHOR\"");
        if (DbUtil.isMssql()) { // Really, Microsoft? You're being weird.
            DbUtil.executeUpdate(connection, "EXEC sp_rename 'COMPONENT.AUTHOR_V48', 'AUTHOR', 'COLUMN'");
        } else if (DbUtil.isMysql()) { // MySQL < 8.0 does not support RENAME COLUMN and needs a special treatment.
            DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" CHANGE \"AUTHOR_V48\" \"AUTHOR\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"COMPONENT\" RENAME COLUMN \"AUTHOR_V48\" TO \"AUTHOR\"");
        }
    }

    private void setJiraPropertyValuesFromJiraToIntegrationGroup(AlpineQueryManager qm, Connection connection) throws Exception {
        LOGGER.info("Setting Jira property values from Groupname 'jira' to Groupname 'integrations'");
        final PreparedStatement ps = connection.prepareStatement("""
            UPDATE "CONFIGPROPERTY" SET "PROPERTYVALUE" = (
                SELECT "PROPERTYVALUE" FROM "CONFIGPROPERTY" 
                WHERE "GROUPNAME" = 'jira' AND "PROPERTYNAME" = ?
            ) WHERE "GROUPNAME" = 'integrations' AND "PROPERTYNAME" = ?
        """);

        ps.setString(1, JIRA_URL.getPropertyName());
        ps.setString(2, JIRA_URL.getPropertyName());
        ps.executeUpdate();

        ps.setString(1, JIRA_USERNAME.getPropertyName());
        ps.setString(2, JIRA_USERNAME.getPropertyName());
        ps.executeUpdate();

        ps.setString(1, JIRA_PASSWORD.getPropertyName());
        ps.setString(2, JIRA_PASSWORD.getPropertyName());
        ps.executeUpdate();

        LOGGER.info("Removing Groupname 'jira'");
        DbUtil.executeUpdate(connection, "DELETE FROM \"CONFIGPROPERTY\" WHERE \"GROUPNAME\" = 'jira'");
    }
}
