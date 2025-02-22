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
import alpine.server.upgrade.UpgradeMetaProcessor;
import org.dependencytrack.upgrade.PreUpgradeHook;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

/**
 * Hook to create the {@code APIKEY.PUBLIC_ID} column and accompanying {@code UNIQUE} index
 * for MSSQL <em>before</em> the main schema migration is executed. The index is partial
 * to allow for multiple {@code NULL} values, which is necessary for the duration of the
 * API key migration performed in {@link v4130_1Updater}.
 *
 * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/4683">GitHub Issue</a>
 * @since 4.13.0
 */
public class v4130PreUpgradeHook implements PreUpgradeHook {

    private static final Logger LOGGER = Logger.getLogger(v4130PreUpgradeHook.class);

    @Override
    public int priority() {
        return 1;
    }

    @Override
    public boolean shouldExecute(final UpgradeMetaProcessor upgradeProcessor) {
        final VersionComparator currentSchemaVersion = upgradeProcessor.getSchemaVersion();
        return currentSchemaVersion != null && currentSchemaVersion.isOlderThan(new VersionComparator("4.13.0"));
    }

    @Override
    public void execute(final Connection connection) throws Exception {
        if (!connection.getMetaData().getDatabaseProductName().equals("Microsoft SQL Server")) {
            LOGGER.info("Database is not MSSQL; Nothing to do");
            return;
        }

        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT 1
                  FROM INFORMATION_SCHEMA.COLUMNS
                 WHERE UPPER(TABLE_NAME) = 'APIKEY'
                   AND UPPER(COLUMN_NAME) = 'PUBLIC_ID'
                """)) {
            if (ps.executeQuery().next()) {
                LOGGER.info("PUBLIC_ID column already exists in APIKEY table; Nothing to do");
                return;
            }
        }

        try (final Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE \"APIKEY\" ADD \"PUBLIC_ID\" VARCHAR(8) NULL");
            stmt.execute("CREATE UNIQUE INDEX \"APIKEY_PUBLIC_IDX\" ON \"APIKEY\"(\"PUBLIC_ID\") WHERE \"PUBLIC_ID\" IS NOT NULL");
        }
    }

}
