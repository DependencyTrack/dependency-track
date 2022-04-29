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
package org.dependencytrack.upgrade.v450;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.upgrade.UpgradeException;
import org.dependencytrack.auth.Permissions;
import alpine.server.util.DbUtil;
import org.apache.commons.io.FileDeleteStrategy;
import org.dependencytrack.auth.Permissions;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class v450Updater extends AbstractUpgradeItem {


    private static final Logger LOGGER = Logger.getLogger(v450Updater.class);
    private static final String STMT_1 = "INSERT INTO \"PERMISSION\" (\"NAME\", \"DESCRIPTION\") VALUES (?, ?)";
    private static final String STMT_2 = "SELECT \"ID\" FROM \"PERMISSION\" WHERE \"NAME\" = ?";
    private static final String STMT_3 = "SELECT \"u\".\"ID\" FROM \"MANAGEDUSER\" AS \"u\" INNER JOIN \"MANAGEDUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"MANAGEDUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_4 = "INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_5 = "SELECT \"u\".\"ID\" FROM \"LDAPUSER\" AS \"u\" INNER JOIN \"LDAPUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"LDAPUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_6 = "INSERT INTO \"LDAPUSERS_PERMISSIONS\" (\"LDAPUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_7 = "SELECT \"u\".\"ID\" FROM \"OIDCUSER\" AS \"u\" INNER JOIN \"OIDCUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"OIDCUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_8 = "INSERT INTO \"OIDCUSERS_PERMISSIONS\" (\"OIDCUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_9 = "SELECT \"t\".\"ID\" FROM \"TEAM\" AS \"t\" INNER JOIN \"TEAMS_PERMISSIONS\" AS \"tp\" ON \"tp\".\"TEAM_ID\" = \"t\".\"ID\" WHERE \"tp\".\"PERMISSION_ID\" = %d";
    private static final String STMT_10 = "INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_11 = "UPDATE \"VULNERABILITY\" SET \"CWE\" = NULL";
    private static final String STMT_12 = "UPDATE \"REPOSITORY\" SET \"URL\" = 'https://packages.atlassian.com/content/repositories/atlassian-public/' WHERE \"TYPE\" = 'MAVEN' AND \"IDENTIFIER\" = 'atlassian-public'";

    @Override
    public String getSchemaVersion() {
        return "4.5.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        LOGGER.info("Deleting NIST directory");
        try {
            final String NIST_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "nist";
            FileDeleteStrategy.FORCE.delete(new File(NIST_ROOT_DIR));
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting the NIST directory", e);
        }

        LOGGER.info("Clearing vulnerability CWEs. CWEs will be recreated when vulnerabilities are next synchronized.");
        DbUtil.executeUpdate(connection, STMT_11);
      
        LOGGER.info("Creating VIEW_POLICY_VIOLATION permission");
        PreparedStatement ps = connection.prepareStatement(STMT_1);
        ps.setString(1, Permissions.VIEW_POLICY_VIOLATION.name());
        ps.setString(2, Permissions.VIEW_POLICY_VIOLATION.getDescription());
        ps.executeUpdate();

        final long viewVulnPermissionId = getPermissionId(connection, Permissions.VIEW_POLICY_VIOLATION);
        final long vulnAnalysisPermissionId = getPermissionId(connection, Permissions.POLICY_VIOLATION_ANALYSIS);

        LOGGER.info("Granting VIEW_POLICY_VIOLATION permission to managed users with POLICY_VIOLATION_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_3, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_4);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_POLICY_VIOLATION permission to LDAP users with POLICY_VIOLATION_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_5, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_6);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_POLICY_VIOLATION permission to OIDC users with POLICY_VIOLATION_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_7, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_8);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_POLICY_VIOLATION permission to teams with POLICY_VIOLATION_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_9, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_10);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Updating Atlassian Maven Repository URL");
        DbUtil.executeUpdate(connection, STMT_12);
    }

    private long getPermissionId(final Connection connection, final Permissions permission) throws SQLException, UpgradeException {
        final PreparedStatement ps = connection.prepareStatement(STMT_2);
        ps.setString(1, permission.name());

        final ResultSet rs = ps.executeQuery();
        if (!rs.next()) {
            throw new UpgradeException("Unable to determine ID of permission " + permission.name());
        }

        return rs.getLong(1);
    }

}
