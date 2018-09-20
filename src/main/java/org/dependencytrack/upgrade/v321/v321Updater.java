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
package org.dependencytrack.upgrade.v321;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.SQLException;

public class v321Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v321Updater.class);
    private static final String STMT_1 = "UPDATE \"VULNERABILITY\" SET \"SOURCE\" = 'NPM' WHERE \"SOURCE\" = 'NSP'";

    public String getSchemaVersion() {
        return "3.2.1";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        LOGGER.info("Migrating vulnerabilities from NSP to NPM");
        DbUtil.executeUpdate(connection, STMT_1);
    }

}