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
package org.dependencytrack.upgrade.v350;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.SQLException;

public class v350Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v350Updater.class);
    private static final String STMT_1 = "UPDATE \"PROJECT\" SET \"NAME\" = '(Undefined)' WHERE \"NAME\" IS NULL OR LTRIM(RTRIM(\"NAME\")) = ''";
    private static final String STMT_2 = "UPDATE \"REPOSITORY\" SET \"URL\" = 'https://api.nuget.org/' WHERE \"IDENTIFIER\" = 'nuget-gallery'";
    private static final String[] UNASSIGNED_METRICS = new String[] {
            "UPDATE \"PORTFOLIOMETRICS\" SET \"UNASSIGNED_SEVERITY\" = 0 WHERE \"UNASSIGNED_SEVERITY\" IS NULL",
            "UPDATE \"PROJECTMETRICS\" SET \"UNASSIGNED_SEVERITY\" = 0 WHERE \"UNASSIGNED_SEVERITY\" IS NULL",
            "UPDATE \"DEPENDENCYMETRICS\" SET \"UNASSIGNED_SEVERITY\" = 0 WHERE \"UNASSIGNED_SEVERITY\" IS NULL",
            "UPDATE \"COMPONENTMETRICS\" SET \"UNASSIGNED_SEVERITY\" = 0 WHERE \"UNASSIGNED_SEVERITY\" IS NULL"
    };
    public String getSchemaVersion() {
        return "3.5.0";
    }

    public void executeUpgrade(AlpineQueryManager aqm, Connection connection) throws SQLException {
        LOGGER.info("Validating project names");
        DbUtil.executeUpdate(connection, STMT_1);

        LOGGER.info("Correcting NuGet API URL");
        DbUtil.executeUpdate(connection, STMT_2);

        LOGGER.info("Adding support for unassigned (severity) metrics");
        for (String statement: UNASSIGNED_METRICS) {
            DbUtil.executeUpdate(connection, statement);
        }
    }

}