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
import alpine.util.DbUtil;
import java.sql.Connection;

public class v320Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v320Updater.class);

    public String getSchemaVersion() {
        return "3.2.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) {
        LOGGER.info("Dropping old/unused columns");
        DbUtil.dropColumn(connection, "PROJECT_PROPERTY", "KEY");
        DbUtil.dropColumn(connection, "PROJECT_PROPERTY", "VALUE");
    }
}