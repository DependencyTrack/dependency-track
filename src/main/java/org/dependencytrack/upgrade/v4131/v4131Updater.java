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
package org.dependencytrack.upgrade.v4131;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class v4131Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4131Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.13.1";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        createTagJoinTablePrimaryKeys(connection);
    }

    private void createTagJoinTablePrimaryKeys(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            final String maybeClustered = DbUtil.isMssql() ? "CLUSTERED" : "";

            LOGGER.info("Creating primary key on \"NOTIFICATIONRULE_TAGS\" table");
            statement.execute(/* language=SQL */ """
                    ALTER TABLE "NOTIFICATIONRULE_TAGS" ADD CONSTRAINT "NOTIFICATIONRULE_TAGS_PK"
                    PRIMARY KEY %s ("NOTIFICATIONRULE_ID", "TAG_ID")
                    """.formatted(maybeClustered));

            LOGGER.info("Creating primary key on \"POLICY_TAGS\" table");
            statement.execute(/* language=SQL */ """
                    ALTER TABLE "POLICY_TAGS" ADD CONSTRAINT "POLICY_TAGS_PK"
                    PRIMARY KEY %s ("POLICY_ID", "TAG_ID")
                    """.formatted(maybeClustered));

            LOGGER.info("Creating primary key on \"PROJECTS_TAGS\" table");
            statement.execute(/* language=SQL */ """
                    ALTER TABLE "PROJECTS_TAGS" ADD CONSTRAINT "PROJECTS_TAGS_PK"
                    PRIMARY KEY %s ("PROJECT_ID", "TAG_ID")
                    """.formatted(maybeClustered));
        }
    }

}
