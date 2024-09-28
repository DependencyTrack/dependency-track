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

import jakarta.json.Json;
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
        migrateAuthorToAuthors(connection);
        dropAuthorColumns(connection);
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

    private void migrateAuthorToAuthors(final Connection connection) throws SQLException {
        LOGGER.info("Migrating PROJECT.AUTHOR and COMPONENT.AUTHOR to PROJECT.AUTHORS and COMPONENT.AUTHORS");

        // MSSQL did not have native JSON functions until version 2022.
        // Since we have to support versions earlier than that, the migration
        // requires a more procedural approach.
        if (DbUtil.isMssql()) {
            migrateAuthorToAuthorsMssql(connection);
            return;
        }

        try (final Statement stmt = connection.createStatement()) {
            if (DbUtil.isH2()) {
                stmt.executeUpdate("""
                        UPDATE "PROJECT"
                           SET "AUTHORS" = JSON_ARRAY(JSON_OBJECT('name': "AUTHOR"))
                         WHERE "AUTHOR" IS NOT NULL
                        """);
                stmt.executeUpdate("""
                        UPDATE "COMPONENT"
                           SET "AUTHORS" = JSON_ARRAY(JSON_OBJECT('name': "AUTHOR"))
                         WHERE "AUTHOR" IS NOT NULL
                        """);
            } else if (DbUtil.isMysql()) {
                stmt.executeUpdate("""
                        UPDATE "PROJECT"
                           SET "AUTHORS" = JSON_ARRAY(JSON_OBJECT('name', "AUTHOR"))
                         WHERE "AUTHOR" IS NOT NULL
                        """);
                stmt.executeUpdate("""
                        UPDATE "COMPONENT"
                           SET "AUTHORS" = JSON_ARRAY(JSON_OBJECT('name', "AUTHOR"))
                         WHERE "AUTHOR" IS NOT NULL
                        """);
            } else if (DbUtil.isPostgreSQL()) {
                stmt.executeUpdate("""
                        UPDATE "PROJECT"
                           SET "AUTHORS" = JSON_BUILD_ARRAY(JSON_BUILD_OBJECT('name', "AUTHOR"))::TEXT
                         WHERE "AUTHOR" IS NOT NULL
                        """);
                stmt.executeUpdate("""
                        UPDATE "COMPONENT"
                           SET "AUTHORS" = JSON_BUILD_ARRAY(JSON_BUILD_OBJECT('name', "AUTHOR"))::TEXT
                         WHERE "AUTHOR" IS NOT NULL
                        """);
            } else {
                throw new IllegalStateException("Unrecognized database type");
            }
        }
    }

    private void migrateAuthorToAuthorsMssql(final Connection connection) throws SQLException {
        migrateAuthorToAuthorsMssqlForTable(connection, "PROJECT");
        migrateAuthorToAuthorsMssqlForTable(connection, "COMPONENT");
    }

    private void migrateAuthorToAuthorsMssqlForTable(
            final Connection connection,
            final String tableName) throws SQLException {
        try (final PreparedStatement selectStatement = connection.prepareStatement("""
                SELECT "ID"
                     , "AUTHOR"
                  FROM "%s"
                 WHERE "AUTHOR" IS NOT NULL
                   AND "AUTHORS" IS NULL
                """.formatted(tableName));
             final PreparedStatement updateStatement = connection.prepareStatement("""
                     UPDATE "%s"
                        SET "AUTHORS" = ?
                      WHERE "ID" = ?
                     """.formatted(tableName))) {
            int batchSize = 0, numBatches = 0, numUpdates = 0;
            final ResultSet rs = selectStatement.executeQuery();
            while (rs.next()) {
                final long id = rs.getLong(1);
                final String author = rs.getString(2);
                final String authors = Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                                .add("name", author))
                        .build()
                        .toString();

                updateStatement.setString(1, authors);
                updateStatement.setLong(2, id);
                updateStatement.addBatch();
                if (++batchSize == 500) {
                    updateStatement.executeBatch();
                    numUpdates += batchSize;
                    numBatches++;
                    batchSize = 0;
                }
            }

            if (batchSize > 0) {
                updateStatement.executeBatch();
                numUpdates += batchSize;
                numBatches++;
            }

            LOGGER.info("Updated %d %s records in %d batches"
                    .formatted(numUpdates, tableName, numBatches));
        }
    }

    private void dropAuthorColumns(final Connection connection) throws SQLException {
        LOGGER.info("Dropping PROJECT.AUTHOR and COMPONENT.AUTHOR columns");

        try (final Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("""
                    ALTER TABLE "PROJECT" DROP COLUMN "AUTHOR"
                    """);
            stmt.executeUpdate("""
                    ALTER TABLE "COMPONENT" DROP COLUMN "AUTHOR"
                    """);
        }
    }

}
