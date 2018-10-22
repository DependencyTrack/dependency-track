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
package org.dependencytrack.upgrade.v330;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.SQLException;

public class v330Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v330Updater.class);

    private static final String[] FINDING_METRICS = new String[] {
            "UPDATE \"PORTFOLIOMETRICS\" SET \"FINDINGS_TOTAL\" = 0 WHERE \"FINDINGS_TOTAL\" IS NULL",
            "UPDATE \"PORTFOLIOMETRICS\" SET \"FINDINGS_AUDITED\" = 0 WHERE \"FINDINGS_AUDITED\" IS NULL",
            "UPDATE \"PORTFOLIOMETRICS\" SET \"FINDINGS_UNAUDITED\" = 0 WHERE \"FINDINGS_UNAUDITED\" IS NULL",

            "UPDATE \"PROJECTMETRICS\" SET \"FINDINGS_TOTAL\" = 0 WHERE \"FINDINGS_TOTAL\" IS NULL",
            "UPDATE \"PROJECTMETRICS\" SET \"FINDINGS_AUDITED\" = 0 WHERE \"FINDINGS_AUDITED\" IS NULL",
            "UPDATE \"PROJECTMETRICS\" SET \"FINDINGS_UNAUDITED\" = 0 WHERE \"FINDINGS_UNAUDITED\" IS NULL",

            "UPDATE \"DEPENDENCYMETRICS\" SET \"FINDINGS_TOTAL\" = 0 WHERE \"FINDINGS_TOTAL\" IS NULL",
            "UPDATE \"DEPENDENCYMETRICS\" SET \"FINDINGS_AUDITED\" = 0 WHERE \"FINDINGS_AUDITED\" IS NULL",
            "UPDATE \"DEPENDENCYMETRICS\" SET \"FINDINGS_UNAUDITED\" = 0 WHERE \"FINDINGS_UNAUDITED\" IS NULL",

            "UPDATE \"COMPONENTMETRICS\" SET \"FINDINGS_TOTAL\" = 0 WHERE \"FINDINGS_TOTAL\" IS NULL",
            "UPDATE \"COMPONENTMETRICS\" SET \"FINDINGS_AUDITED\" = 0 WHERE \"FINDINGS_AUDITED\" IS NULL",
            "UPDATE \"COMPONENTMETRICS\" SET \"FINDINGS_UNAUDITED\" = 0 WHERE \"FINDINGS_UNAUDITED\" IS NULL"
    };


    public String getSchemaVersion() {
        return "3.3.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        LOGGER.info("Adding support for audited and unaudited metrics");
        for (String statement: FINDING_METRICS) {
            DbUtil.executeUpdate(connection, statement);
        }
    }

}