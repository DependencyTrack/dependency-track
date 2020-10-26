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
package org.dependencytrack.upgrade.v410;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;

import java.sql.Connection;

public class v410Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v410Updater.class);
    private static final String COMPOSER_REPOSITORY = "INSERT INTO \"REPOSITORY\" (\"TYPE\", \"IDENTIFIER\", \"URL\", \"RESOLUTION_ORDER\", \"ENABLED\", \"INTERNAL\") VALUES ('COMPOSER', 'packagist', 'https://repo.packagist.org/', 1, TRUE, FALSE)";
    private static final String COMPOSER_REPOSITORY_ALT = "INSERT INTO \"REPOSITORY\" (\"TYPE\", \"IDENTIFIER\", \"URL\", \"RESOLUTION_ORDER\", \"ENABLED\", \"INTERNAL\") VALUES ('COMPOSER', 'packagist', 'https://repo.packagist.org/', 1, 1, 0)";

    @Override
    public String getSchemaVersion() {
        return "4.1.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager alpineQueryManager, final Connection connection) throws Exception {
        LOGGER.info("Adding Composer-type repository support");
        try {
            DbUtil.executeUpdate(connection, COMPOSER_REPOSITORY);
        } catch (Exception e) {
            LOGGER.info("Enabled and/or internal fields are likely not boolean. Attempting composer repository creation assuming bit fields");
            DbUtil.executeUpdate(connection, COMPOSER_REPOSITORY_ALT);
        }
    }
}
