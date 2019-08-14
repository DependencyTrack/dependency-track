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
package org.dependencytrack.upgrade.v340;

import alpine.Config;
import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import org.apache.commons.io.FileDeleteStrategy;
import org.dependencytrack.search.IndexManager;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

public class v340Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v340Updater.class);


    public String getSchemaVersion() {
        return "3.4.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        LOGGER.info("Recreating table PROJECT_PROPERTY");
        DbUtil.dropTable(connection, "PROJECT_PROPERTY"); // Will be dynamically recreated

        LOGGER.info("Deleting search engine indices");
        IndexManager.delete(IndexManager.IndexType.LICENSE);
        IndexManager.delete(IndexManager.IndexType.PROJECT);
        IndexManager.delete(IndexManager.IndexType.COMPONENT);
        IndexManager.delete(IndexManager.IndexType.VULNERABILITY);

        LOGGER.info("Deleting Dependency-Check work directory");
        try {
            final String DC_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "dependency-check";
            FileDeleteStrategy.FORCE.delete(new File(DC_ROOT_DIR));
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting the Dependency-Check work directory", e);
        }
    }

}