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
package org.dependencytrack.upgrade.v4140;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.tasks.NistMirrorTask;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;

public class v4140Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4140Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.14.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        addRiskMatrixColumns(connection);
        createVulnerabilitySequenceV2Table(connection);
        addConfigProperties(connection);
        addSourceOfDiscoveryColumn(connection);
        resetVulnSourceWatermarks(connection);
        deleteNvdFeedTimestampFiles();
    }

    private void addRiskMatrixColumns(final Connection connection) throws Exception {
        LOGGER.info("Adding risk matrix columns to \"ANALYSIS\" table");
        addVarcharColumnIfMissing(connection, "RISK_IMPACT", 32);
        addVarcharColumnIfMissing(connection, "RISK_LIKELIHOOD", 64);
        addVarcharColumnIfMissing(connection, "RESIDUAL_RISK_IMPACT", 32);
        addVarcharColumnIfMissing(connection, "RESIDUAL_RISK_LIKELIHOOD", 64);
        addDoubleColumnIfMissing(connection, "RISK_SCORE");
        addDoubleColumnIfMissing(connection, "RESIDUAL_RISK_SCORE");
        if (!columnExists(connection, "ANALYSIS", "RISK_JUSTIFICATION")) {
            if (DbUtil.isH2()) {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RISK_JUSTIFICATION\" CLOB");
            } else if (DbUtil.isMysql()) {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RISK_JUSTIFICATION\" MEDIUMTEXT");
            } else {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RISK_JUSTIFICATION\" TEXT");
            }
        }
        if (!columnExists(connection, "ANALYSIS", "RESIDUAL_RISK_JUSTIFICATION")) {
            if (DbUtil.isH2()) {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RESIDUAL_RISK_JUSTIFICATION\" CLOB");
            } else if (DbUtil.isMysql()) {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RESIDUAL_RISK_JUSTIFICATION\" MEDIUMTEXT");
            } else {
                DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"RESIDUAL_RISK_JUSTIFICATION\" TEXT");
            }
        }
    }

    private void addVarcharColumnIfMissing(final Connection connection, final String columnName, final int length) throws SQLException {
        if (columnExists(connection, "ANALYSIS", columnName)) {
            return;
        }
        DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"" + columnName + "\" VARCHAR(" + length + ")");
    }

    private void addDoubleColumnIfMissing(final Connection connection, final String columnName) throws SQLException {
        if (columnExists(connection, "ANALYSIS", columnName)) {
            return;
        }
        if (DbUtil.isMssql()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"" + columnName + "\" FLOAT");
        } else if (DbUtil.isPostgreSQL()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"" + columnName + "\" DOUBLE PRECISION");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"ANALYSIS\" ADD \"" + columnName + "\" DOUBLE");
        }
    }

    private boolean columnExists(final Connection connection, final String tableName, final String columnName) throws SQLException {
        final DatabaseMetaData meta = connection.getMetaData();
        final String catalog = connection.getCatalog();
        final String schema = connection.getSchema();

        if (lookupColumn(meta, catalog, schema, tableName, columnName)) {
            return true;
        }
        if (lookupColumn(meta, catalog, schema, tableName.toUpperCase(Locale.ROOT), columnName.toUpperCase(Locale.ROOT))) {
            return true;
        }
        if (lookupColumn(meta, catalog, schema, tableName.toLowerCase(Locale.ROOT), columnName.toLowerCase(Locale.ROOT))) {
            return true;
        }
        return false;
    }

    private boolean lookupColumn(final DatabaseMetaData metaData, final String catalog, final String schema,
                                 final String tablePattern, final String columnPattern) throws SQLException {
        try (ResultSet columns = metaData.getColumns(catalog, schema, tablePattern, columnPattern)) {
            return columns.next();
        }
    }

    private void deleteNvdFeedTimestampFiles() {
        final Path nvdMirrorDir = NistMirrorTask.DEFAULT_NVD_MIRROR_DIR;
        if (!Files.isDirectory(nvdMirrorDir)) {
            return;
        }

        LOGGER.info("Deleting NVD feed timestamp files to force re-download");
        try (final DirectoryStream<Path> stream = Files.newDirectoryStream(nvdMirrorDir, "*.json.gz.ts")) {
            for (final Path tsFile : stream) {
                LOGGER.info("Deleting " + tsFile.getFileName());
                Files.delete(tsFile);
            }
        } catch (IOException e) {
            LOGGER.warn("Failed to delete NVD feed timestamp files. You may need to delete them manually and restart Dependency-Track to force a re-download.", e);
        }
    }

    private void createVulnerabilitySequenceV2Table(final Connection connection) throws Exception {
        if (tableExists(connection, "VULNERABILITY_SEQUENCE_V2")) {
            LOGGER.debug("VULNERABILITY_SEQUENCE_V2 table already exists, skipping creation");
            return;
        }

        LOGGER.info("Creating VULNERABILITY_SEQUENCE_V2 table");
        final String dbProductName = connection.getMetaData().getDatabaseProductName().toLowerCase();
        final boolean isSqlServer = dbProductName.contains("sql server") || dbProductName.contains("microsoft");

        final String createTableSql = isSqlServer
                ? """
                CREATE TABLE "VULNERABILITY_SEQUENCE_V2" (
                    "ID" BIGINT IDENTITY(1,1) NOT NULL,
                    "ORG_CODE" VARCHAR(64) NOT NULL,
                    "PROJECT_KEY" VARCHAR(128) NOT NULL,
                    "CURRENT_SEQUENCE" BIGINT NOT NULL DEFAULT 0,
                    "LAST_RESET_DATE" DATETIME,
                    "RESET_POLICY" VARCHAR(32) NOT NULL,
                    "CREATED_AT" DATETIME DEFAULT GETDATE(),
                    PRIMARY KEY ("ID"),
                    CONSTRAINT "VULNSEQV2_ORG_PROJECT_IDX" UNIQUE ("ORG_CODE", "PROJECT_KEY")
                )
                """
                : """
                CREATE TABLE "VULNERABILITY_SEQUENCE_V2" (
                    "ID" BIGINT GENERATED BY DEFAULT AS IDENTITY (START WITH 1) NOT NULL,
                    "ORG_CODE" VARCHAR(64) NOT NULL,
                    "PROJECT_KEY" VARCHAR(128) NOT NULL,
                    "CURRENT_SEQUENCE" BIGINT NOT NULL DEFAULT 0,
                    "LAST_RESET_DATE" TIMESTAMP,
                    "RESET_POLICY" VARCHAR(32) NOT NULL,
                    "CREATED_AT" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY ("ID"),
                    CONSTRAINT "VULNSEQV2_ORG_PROJECT_IDX" UNIQUE ("ORG_CODE", "PROJECT_KEY")
                )
                """;
        DbUtil.executeUpdate(connection, createTableSql);

        DbUtil.executeUpdate(connection, """
                CREATE INDEX "VULNSEQV2_ORG_IDX" ON "VULNERABILITY_SEQUENCE_V2" ("ORG_CODE")
                """);
        DbUtil.executeUpdate(connection, """
                CREATE INDEX "VULNSEQV2_PROJECT_IDX" ON "VULNERABILITY_SEQUENCE_V2" ("PROJECT_KEY")
                """);
    }

    private void addConfigProperties(final Connection connection) throws SQLException {
        createConfigPropertyIfAbsent(connection, ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE);
        createConfigPropertyIfAbsent(connection, ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE);
        createConfigPropertyIfAbsent(connection, ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE);
        createConfigPropertyIfAbsent(connection, ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY);
        createConfigPropertyIfAbsent(connection, ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING);
    }

    private void createConfigPropertyIfAbsent(final Connection connection, final ConfigPropertyConstants property) throws SQLException {
        if (configPropertyExists(connection, property.getGroupName(), property.getPropertyName())) {
            LOGGER.debug("ConfigProperty already exists, skipping: " + property.name());
            return;
        }

        try (PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO "CONFIGPROPERTY" (
                  "DESCRIPTION"
                , "GROUPNAME"
                , "PROPERTYNAME"
                , "PROPERTYTYPE"
                , "PROPERTYVALUE"
                ) VALUES (?, ?, ?, ?, ?)
                """)) {
            ps.setString(1, property.getDescription());
            ps.setString(2, property.getGroupName());
            ps.setString(3, property.getPropertyName());
            ps.setString(4, property.getPropertyType().name());
            ps.setString(5, property.getDefaultPropertyValue());
            ps.executeUpdate();
        }
    }

    private boolean configPropertyExists(final Connection connection, final String groupName, final String propertyName)
            throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement("""
                SELECT 1
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = ?
                   AND "PROPERTYNAME" = ?
                """)) {
            ps.setString(1, groupName);
            ps.setString(2, propertyName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean tableExists(final Connection connection, final String tableName) throws SQLException {
        final DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet rs = metaData.getTables(null, null, tableName, new String[]{"TABLE"})) {
            return rs.next();
        }
    }

    private void addSourceOfDiscoveryColumn(final Connection connection) throws SQLException {
        LOGGER.info("Adding SOURCE_OF_DISCOVERY column to \"VULNERABILITY\" table");
        if (columnExists(connection, "VULNERABILITY", "SOURCE_OF_DISCOVERY")) {
            return;
        }
        DbUtil.executeUpdate(connection,
                "ALTER TABLE \"VULNERABILITY\" ADD \"SOURCE_OF_DISCOVERY\" VARCHAR(255)");
    }

    private void resetVulnSourceWatermarks(final Connection connection) throws SQLException {
        LOGGER.info("Resetting watermarks for incremental vulnerability source mirroring. Sources will perform a full mirror for their next scheduled invocation.");
        try (final Statement statement = connection.createStatement()) {
            statement.execute(/* language=SQL */ """
                    UPDATE "CONFIGPROPERTY"
                       SET "PROPERTYVALUE" = NULL
                     WHERE "GROUPNAME" = 'vuln-source'
                       AND "PROPERTYNAME" = 'github.advisories.last.modified.epoch.seconds'
                    """);
            statement.execute(/* language=SQL */ """
                    UPDATE "CONFIGPROPERTY"
                       SET "PROPERTYVALUE" = NULL
                     WHERE "GROUPNAME" = 'vuln-source'
                       AND "PROPERTYNAME" = 'nvd.api.last.modified.epoch.seconds'
                    """);
        }
    }
}
