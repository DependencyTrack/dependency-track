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
package org.dependencytrack.upgrade.v4136;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Creates an index on VULNERABLESOFTWARE table to optimize PURL lookups with VERSION.
 * This addresses performance issues when querying by PURL components and VERSION
 * on large datasets (>25M rows), preventing heap page thrashing.
 *
 * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/5710">GitHub Issue</a>
 * @since 4.13.6
 */
public class v4136Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4136Updater.class);
    private static final String INDEX_NAME = "VULNERABLESOFTWARE_FULL_PURL_IDX";
    private static final String TABLE_NAME = "VULNERABLESOFTWARE";

    @Override
    public String getSchemaVersion() {
        return "4.13.6";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        createVulnerableSoftwarePurlVersionIndex(connection);
    }

    private void createVulnerableSoftwarePurlVersionIndex(final Connection connection) throws SQLException {
        if (indexExists(connection)) {
            LOGGER.info("Index %s already exists; skipping creation".formatted(INDEX_NAME));
            return;
        }

        LOGGER.info("Creating index %s on %s table".formatted(INDEX_NAME, TABLE_NAME));

        try (final Statement statement = connection.createStatement()) {
            if (DbUtil.isPostgreSQL()) {
                statement.execute(/* language=SQL */ """
                        CREATE INDEX "%s" ON "%s" ("PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME", "VERSION")
                        """.formatted(INDEX_NAME, TABLE_NAME));
            } else if (DbUtil.isMssql()) {
                statement.execute(/* language=SQL */ """
                        CREATE INDEX "%s" ON "%s" ("PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME", "VERSION")
                        """.formatted(INDEX_NAME, TABLE_NAME));
            } else if (DbUtil.isMysql()) {
                statement.execute(/* language=SQL */ """
                        CREATE INDEX `%s` ON `%s` (`PURL_TYPE`, `PURL_NAMESPACE`, `PURL_NAME`, `VERSION`)
                        """.formatted(INDEX_NAME, TABLE_NAME));
            } else if (DbUtil.isH2()) {
                statement.execute(/* language=SQL */ """
                        CREATE INDEX "%s" ON "%s" ("PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME", "VERSION")
                        """.formatted(INDEX_NAME, TABLE_NAME));
            } else {
                throw new IllegalStateException(
                        "Unsupported database: " + connection.getMetaData().getDatabaseProductName());
            }

            LOGGER.info("Successfully created index %s".formatted(INDEX_NAME));
        }
    }

    private boolean indexExists(final Connection connection) throws SQLException {
        try (final ResultSet rs = connection.getMetaData().getIndexInfo(null, null, TABLE_NAME, false, false)) {
            while (rs.next()) {
                final String indexName = rs.getString("INDEX_NAME");
                if (INDEX_NAME.equalsIgnoreCase(indexName)) {
                    return true;
                }
            }
        }
        return false;
    }
}
