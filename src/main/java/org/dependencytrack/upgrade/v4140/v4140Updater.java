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
package org.dependencytrack.upgrade.v4140;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class v4140Updater extends AbstractUpgradeItem {
    private static final Logger LOGGER = Logger.getLogger(v4140Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.14.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        normalizeCpeData(connection);
    }

    private void normalizeCpeData(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            LOGGER.info("Adding CVSSv4 columns to \"VULNERABILITY\"");
            statement.execute(/* language=SQL */ """
                    ALTER TABLE "VULNERABILITY"
                        ADD COLUMN "CVSSV4BASESCORE"    numeric,
                        ADD COLUMN "CVSSV4EXPLOITSCORE" numeric,
                        ADD COLUMN "CVSSV4IMPACTSCORE"  numeric,
                        ADD COLUMN "CVSSV4VECTOR"       varchar(255);
                    """);
        }
    }
}
