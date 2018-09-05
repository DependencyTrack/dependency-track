/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v320;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.upgrade.UpgradeMetaProcessor;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.SQLException;

public class v320Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v320Updater.class);

    public String getSchemaVersion() {
        return "3.2.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        LOGGER.info("Dropping old/unused columns");
        if (DbUtil.columnExists(connection, "PROJECT_PROPERTY", "KEY")) {
            DbUtil.dropColumn(connection, "PROJECT_PROPERTY", "KEY");
        }
        if (DbUtil.columnExists(connection, "PROJECT_PROPERTY", "VALUE")) {
            DbUtil.dropColumn(connection, "PROJECT_PROPERTY", "VALUE");
        }
    }

    /**
     * Overriding due to an issue with Dependency-Track 3.1.x and PostgreSQL upgrade framework incompatability.
     */
    public boolean shouldUpgrade(AlpineQueryManager queryManager, Connection connection) {
        try {
            UpgradeMetaProcessor ump = new UpgradeMetaProcessor(connection);
            if (!ump.hasUpgradeRan(this.getClass())) {
                return true;
            }
        } catch (SQLException e) {
            LOGGER.error("Error determining if upgrade should execute", e);
        }
        return false;
    }
}