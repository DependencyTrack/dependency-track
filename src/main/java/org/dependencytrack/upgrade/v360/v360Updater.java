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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v360;

import alpine.Config;
import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import org.apache.commons.io.FileDeleteStrategy;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

public class v360Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v360Updater.class);
    private static final String STMT_1 = "UPDATE \"PROJECT\" SET \"ACTIVE\" = TRUE WHERE \"ACTIVE\" IS NULL";
    private static final String STMT_1_ALT = "UPDATE \"PROJECT\" SET \"ACTIVE\" = 1 WHERE \"ACTIVE\" IS NULL";
    private static final String STMT_2 = "DELETE FROM \"CONFIGPROPERTY\" WHERE \"GROUPNAME\" = 'scanner' AND \"PROPERTYNAME\" = 'dependencycheck.enabled'";

    public String getSchemaVersion() {
        return "3.6.0";
    }

    public void executeUpgrade(AlpineQueryManager aqm, Connection connection) throws SQLException {
        LOGGER.info("Updating project active status. Setting all projects to active");
        try {
            DbUtil.executeUpdate(connection, STMT_1);
        } catch (Exception e) {
            LOGGER.info("Active field is likely not boolean. Attempting project active status update assuming bit field");
            DbUtil.executeUpdate(connection, STMT_1_ALT);
        }

        LOGGER.info("Removing legacy Dependency-Check configuration settings");
        DbUtil.executeUpdate(connection, STMT_2);

        LOGGER.info("Deleting Dependency-Check work directory");
        try {
            final String DC_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "dependency-check";
            FileDeleteStrategy.FORCE.delete(new File(DC_ROOT_DIR));
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting the Dependency-Check work directory", e);
        }

        LOGGER.info("Dropping unused evidence table");
        DbUtil.dropTable(connection, "EVIDENCE");

        LOGGER.info("Dropping unused CPE database fields from the Vulnerability object");
        DbUtil.dropColumn(connection, "VULNERABILITY", "MATCHEDCPE");
        DbUtil.dropColumn(connection, "VULNERABILITY", "MATCHEDALLPREVIOUSCPE");
    }

}
