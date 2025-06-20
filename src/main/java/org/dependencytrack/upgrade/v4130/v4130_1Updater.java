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
package org.dependencytrack.upgrade.v4130;

import alpine.common.logging.Logger;
import alpine.common.util.VersionComparator;
import alpine.model.ApiKey;
import alpine.persistence.AlpineQueryManager;
import alpine.security.ApiKeyDecoder;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.upgrade.UpgradeMetaProcessor;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class v4130_1Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4130Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.13.0";
    }

    @Override
    public boolean shouldUpgrade(final AlpineQueryManager qm, final Connection connection) {
        // Modified from AbstractUpgradeItem#shouldUpgrade to run this updater,
        // even if the schema version is already 4.13.0, IF v4130Updater ran before.
        //
        // This is to support users running snapshot builds of v4.13.0, for whom the
        // initial API key migration failed: https://github.com/DependencyTrack/dependency-track/issues/4652.

        final UpgradeMetaProcessor upgradeMetaProcessor = new UpgradeMetaProcessor(connection);
        final boolean didOldUpgradeVersionRun;
        try {
            didOldUpgradeVersionRun = upgradeMetaProcessor.hasUpgradeRan(v4130Updater.class);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to check whether %s ran before".formatted(v4130Updater.class), e);
        }

        final VersionComparator currentVersion = upgradeMetaProcessor.getSchemaVersion();
        if (currentVersion == null) {
            return false;
        }

        final VersionComparator version = new VersionComparator(this.getSchemaVersion());
        return version.isNewerThan(currentVersion)
               || (version.equals(currentVersion) && didOldUpgradeVersionRun);
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        migrateToHashedApiKey(connection);
        changeJdbcTypeOfConfigPropertyValueColumn(connection);
    }

    private void migrateToHashedApiKey(final Connection connection) throws Exception {
        LOGGER.info("Performing API key migration");

        final boolean shouldReEnableAutoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        boolean committed = false;

        try (final PreparedStatement selectLegacyKeysStatement = connection.prepareStatement("""
                SELECT "ID"
                     , "APIKEY"
                  FROM "APIKEY"
                 WHERE "PUBLIC_ID" IS NULL
                """);
             final PreparedStatement updateLegacyKeysStatement = connection.prepareStatement("""
                     UPDATE "APIKEY"
                        SET "SECRET_HASH" = ?
                          , "PUBLIC_ID" = ?
                          , "IS_LEGACY" = ?
                          , "APIKEY" = ?
                      WHERE "ID" = ?
                     """);
             // Legacy keys that were migrated by a previous SNAPSHOT version of v4.13.0, and have not been regenerated yet,
             // *or* non-legacy keys that were created by a previous SNAPSHOT version of v4.13.0.
             //
             // For these keys, the APIKEY column already contains the hashed secret value.
             // NB: MSSQL doesn't have a boolean type and doesn't support expressions such
             // as `NOT "IS_LEGACY"`, hence the need to use parameters instead.
             final PreparedStatement updateMigratedKeysStatement = connection.prepareStatement("""
                     UPDATE "APIKEY"
                        SET "SECRET_HASH" = "APIKEY"
                          , "APIKEY" = CONCAT('migrated-', CAST("ID" AS VARCHAR))
                      WHERE ("IS_LEGACY" = ? AND "APIKEY" NOT LIKE 'migrated-%')
                         OR ("IS_LEGACY" = ? AND "PUBLIC_ID" IS NOT NULL AND "SECRET_HASH" IS NULL)
                     """)) {
            final ResultSet rs = selectLegacyKeysStatement.executeQuery();
            while (rs.next()) {
                final long apiKeyId = rs.getLong("ID");
                final ApiKey decodedApiKey = ApiKeyDecoder.decode(rs.getString("APIKEY"));

                // Perform some sanity checks and fail the migration if anything looks odd.
                // Best to fail the migration entirely than to mess up any API keys.
                if (!decodedApiKey.isLegacy()) {
                    throw new IllegalStateException("""
                            Unable to migrate API key with ID %d: Failed to recognize \
                            it as legacy format.""".formatted(apiKeyId));
                }
                if (decodedApiKey.getSecretHash() == null) {
                    throw new IllegalStateException("""
                            Unable to migrate API key with ID %d: No secret hash generated \
                            during conversion.""".formatted(apiKeyId));
                }
                if (decodedApiKey.getPublicId() == null) {
                    throw new IllegalStateException("""
                            Unable to migrate API key with ID %d: No public ID determined \
                            during conversion.""".formatted(apiKeyId));
                }

                updateLegacyKeysStatement.setString(1, decodedApiKey.getSecretHash());
                updateLegacyKeysStatement.setString(2, decodedApiKey.getPublicId());
                if (DbUtil.isMysql() || DbUtil.isMssql()) {
                    updateLegacyKeysStatement.setInt(3, 1);
                } else {
                    updateLegacyKeysStatement.setBoolean(3, true);
                }
                updateLegacyKeysStatement.setString(4, "migrated-" + apiKeyId);
                updateLegacyKeysStatement.setLong(5, apiKeyId);
                updateLegacyKeysStatement.executeUpdate();

                LOGGER.info("Migrated legacy API key with ID " + apiKeyId);
            }

            if (DbUtil.isMysql() || DbUtil.isMssql()) {
                updateMigratedKeysStatement.setInt(1, 0);
                updateMigratedKeysStatement.setInt(2, 1);
            } else {
                updateMigratedKeysStatement.setBoolean(1, false);
                updateMigratedKeysStatement.setBoolean(2, true);
            }
            final int updatedMigratedKeys = updateMigratedKeysStatement.executeUpdate();
            if (updatedMigratedKeys > 0) {
                LOGGER.info("Updated %d previously migrated keys".formatted(updatedMigratedKeys));
            }

            connection.commit();
        } finally {
            if (!committed) {
                connection.rollback();
            }

            if (shouldReEnableAutoCommit) {
                connection.setAutoCommit(true);
            }
        }

        LOGGER.info("API key migration completed; Dropping \"APIKEY\" column from \"APIKEY\" table");
        try (final Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE \"APIKEY\" DROP CONSTRAINT \"APIKEY_IDX\"");
            statement.execute("ALTER TABLE \"APIKEY\" DROP COLUMN \"APIKEY\"");
        }
    }

    private void changeJdbcTypeOfConfigPropertyValueColumn(final Connection connection) throws Exception {
        // Required to support https://github.com/stevespringett/Alpine/pull/722.
        // The JDBC type "CLOB" is mapped to the type CLOB for H2, MEDIUMTEXT for MySQL, and TEXT for PostgreSQL and SQL Server.
        LOGGER.info("Changing JDBC type of \"CONFIGPROPERTY\".\"PROPERTYVALUE\" from VARCHAR to CLOB");
        if (DbUtil.isH2()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" ADD \"PROPERTYVALUE_V48\" CLOB");
        } else if (DbUtil.isMysql()) {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" ADD \"PROPERTYVALUE_V48\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" ADD \"PROPERTYVALUE_V48\" TEXT");
        }
        DbUtil.executeUpdate(connection, "UPDATE \"CONFIGPROPERTY\" SET \"PROPERTYVALUE_V48\" = \"PROPERTYVALUE\"");
        DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" DROP COLUMN \"PROPERTYVALUE\"");
        if (DbUtil.isMssql()) { // Really, Microsoft? You're being weird.
            DbUtil.executeUpdate(connection, "EXEC sp_rename 'CONFIGPROPERTY.PROPERTYVALUE_V48', 'PROPERTYVALUE', 'COLUMN'");
        } else if (DbUtil.isMysql()) { // MySQL < 8.0 does not support RENAME COLUMN and needs a special treatment.
            DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" CHANGE \"PROPERTYVALUE_V48\" \"PROPERTYVALUE\" MEDIUMTEXT");
        } else {
            DbUtil.executeUpdate(connection, "ALTER TABLE \"CONFIGPROPERTY\" RENAME COLUMN \"PROPERTYVALUE_V48\" TO \"PROPERTYVALUE\"");
        }
    }

}
