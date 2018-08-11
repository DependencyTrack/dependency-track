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
package org.dependencytrack.upgrade.v310;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.upgrade.UpgradeMetaProcessor;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.SQLException;

public class v310Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v310Updater.class);
    private static final String STMT_1 = "UPDATE \"PORTFOLIOMETRICS\" SET \"DEPENDENCIES\" = 0 WHERE \"DEPENDENCIES\" IS NULL";
    private static final String STMT_2 = "UPDATE \"PORTFOLIOMETRICS\" SET \"VULNERABLEDEPENDENCIES\" = 0 WHERE \"VULNERABLEDEPENDENCIES\" IS NULL";

    public String getSchemaVersion() {
        return "3.1.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        DbUtil.executeUpdate(connection, STMT_1);
        DbUtil.executeUpdate(connection, STMT_2);
    }

    /**
     * This upgrade should be executed for all 3.1.x and previous versions. The execution is overwritten
     * due to v3.0.x not including the upgrade framework and thus, the previous schema version being non-existent.
     * For non-existent schemas, the current version is used. Therefore, on 3.0.x upgrades to 3.1.x, the schema
     * version will default to 3.1.x yet the schema will actually be in a 3.0.x state, so we force the upgrade
     * in this scenario.
     *
     * NOTE: This will require upgrades to 3.2 and higher to be running 3.1.x prior to upgrading.
     */
    @Override
    public boolean shouldUpgrade(AlpineQueryManager queryManager, Connection connection) {
        try {
            UpgradeMetaProcessor ump = new UpgradeMetaProcessor(connection);
            if (ump.getSchemaVersion().toString().startsWith("3.1.") && !ump.hasUpgradeRan(this.getClass())) {
                return true;
            }
        } catch (SQLException e) {
            LOGGER.error("Error determining if upgrade should execute", e);
        }
        return false;
    }
}