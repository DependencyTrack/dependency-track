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
package org.dependencytrack.upgrade.v4122;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

public class v4122Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4122Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.12.2";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        fixProjectActiveNullValues(connection);
    }

    private static void fixProjectActiveNullValues(final Connection connection) throws SQLException {
        LOGGER.info("Setting active flag to true for projects where it's currently null");
        try (final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "PROJECT"
                   SET "ACTIVE" = ?
                 WHERE "ACTIVE" IS NULL;
                """)) {
            ps.setBoolean(1, true);

            final int modifiedProjects = ps.executeUpdate();
            LOGGER.info("Updated active flag of %d projects".formatted(modifiedProjects));
        }

        LOGGER.info("Setting default value of the project active flag to true");
        try (final Statement stmt = connection.createStatement()) {
            if (DbUtil.isMssql()) {
                stmt.executeUpdate("""
                        ALTER TABLE "PROJECT"
                          ADD DEFAULT 'true'
                          FOR "ACTIVE";
                        """);
            } else if (DbUtil.isMysql()) {
                stmt.executeUpdate("""
                         ALTER TABLE "PROJECT"
                        MODIFY COLUMN "ACTIVE" BIT(1) DEFAULT 1;
                        """);
            } else if (DbUtil.isPostgreSQL() || DbUtil.isH2()) {
                stmt.executeUpdate("""
                        ALTER TABLE "PROJECT"
                        ALTER COLUMN "ACTIVE"
                          SET DEFAULT TRUE;
                        """);
            } else {
                throw new IllegalStateException(
                        "Unsupported database: " + connection.getMetaData().getDatabaseProductName());
            }
        }
    }

}
