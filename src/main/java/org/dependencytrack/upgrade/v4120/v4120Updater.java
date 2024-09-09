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
package org.dependencytrack.upgrade.v4120;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.BomValidationMode;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_MODE;

public class v4120Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4120Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.12.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        removeExperimentalBomUploadProcessingV2ConfigProperty(connection);
        migrateBomValidationConfigProperty(connection);
        extendTeamNameColumnMaxLength(connection);
    }

    private static void removeExperimentalBomUploadProcessingV2ConfigProperty(final Connection connection) throws SQLException {
        final var propertyGroup = "experimental";
        final var propertyName = "bom.processing.task.v2.enabled";

        LOGGER.info("Removing ConfigProperty %s:%s".formatted(propertyGroup, propertyName));

        try (final PreparedStatement ps = connection.prepareStatement("""
                DELETE
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = ?
                   AND "PROPERTYNAME" = ?
                """)) {
            ps.setString(1, propertyGroup);
            ps.setString(2, propertyName);
            ps.executeUpdate();
        }
    }

    private static void migrateBomValidationConfigProperty(final Connection connection) throws SQLException {
        final boolean shouldReEnableAutoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        boolean committed = false;

        final String bomValidationEnabledGroupName = "artifact";
        final String bomValidationEnabledPropertyName = "bom.validation.enabled";

        LOGGER.info("Migrating ConfigProperty %s:%s to %s:%s"
                .formatted(bomValidationEnabledGroupName, bomValidationEnabledPropertyName,
                        BOM_VALIDATION_MODE.getGroupName(), BOM_VALIDATION_MODE.getPropertyName()));

        try {
            LOGGER.debug("Determining current value of ConfigProperty %s:%s"
                    .formatted(bomValidationEnabledGroupName, bomValidationEnabledPropertyName));
            final String validationEnabledValue;
            try (final PreparedStatement ps = connection.prepareStatement("""
                    SELECT "PROPERTYVALUE"
                      FROM "CONFIGPROPERTY"
                     WHERE "GROUPNAME" = ?
                       AND "PROPERTYNAME" = ?
                    """)) {
                ps.setString(1, bomValidationEnabledGroupName);
                ps.setString(2, bomValidationEnabledPropertyName);
                final ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    validationEnabledValue = rs.getString(1);
                } else {
                    validationEnabledValue = "true";
                }
            }

            final BomValidationMode validationModeValue = "false".equals(validationEnabledValue)
                    ? BomValidationMode.DISABLED
                    : BomValidationMode.ENABLED;

            LOGGER.debug("Creating ConfigProperty %s:%s with value %s"
                    .formatted(BOM_VALIDATION_MODE.getGroupName(), BOM_VALIDATION_MODE.getPropertyName(), validationModeValue));
            try (final PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO "CONFIGPROPERTY" (
                      "DESCRIPTION"
                    , "GROUPNAME"
                    , "PROPERTYNAME"
                    , "PROPERTYTYPE"
                    , "PROPERTYVALUE"
                    ) VALUES (?, ?, ?, ?, ?)
                    """)) {
                ps.setString(1, BOM_VALIDATION_MODE.getDescription());
                ps.setString(2, BOM_VALIDATION_MODE.getGroupName());
                ps.setString(3, BOM_VALIDATION_MODE.getPropertyName());
                ps.setString(4, BOM_VALIDATION_MODE.getPropertyType().name());
                ps.setString(5, validationModeValue.name());
                ps.executeUpdate();
            }

            LOGGER.debug("Removing ConfigProperty %s:%s".formatted(bomValidationEnabledGroupName, bomValidationEnabledPropertyName));
            try (final PreparedStatement ps = connection.prepareStatement("""
                    DELETE
                      FROM "CONFIGPROPERTY"
                     WHERE "GROUPNAME" = ?
                       AND "PROPERTYNAME" = ?
                    """)) {
                ps.setString(1, bomValidationEnabledGroupName);
                ps.setString(2, bomValidationEnabledPropertyName);
                ps.executeUpdate();
            }

            connection.commit();
            committed = true;
        } finally {
            if (!committed) {
                connection.rollback();
            }

            if (shouldReEnableAutoCommit) {
                connection.setAutoCommit(true);
            }
        }
    }

    private void extendTeamNameColumnMaxLength(final Connection connection) throws SQLException {
        LOGGER.info("Extending max length of column TEAM.NAME to 255");

        try (final Statement stmt = connection.createStatement()) {
            if (DbUtil.isMssql()) {
                stmt.executeUpdate("""
                        ALTER TABLE "TEAM" ALTER COLUMN "NAME" VARChAR(255) NOT NULL
                        """);
            } else if (DbUtil.isMysql()) {
                stmt.executeUpdate("""
                    ALTER TABLE "TEAM" MODIFY "NAME" VARCHAR(255) NOT NULL
                    """);
            } else {
                stmt.executeUpdate("""
                    ALTER TABLE "TEAM" ALTER COLUMN "NAME" TYPE VARCHAR(255)
                    """);
            }
        }
    }

}
