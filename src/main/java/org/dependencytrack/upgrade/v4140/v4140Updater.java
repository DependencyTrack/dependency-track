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

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
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
}
