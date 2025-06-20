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
package org.dependencytrack.upgrade.v4100;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

public class v4100Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4100Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.10.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        dropCpeTable(connection);
        authRequiredForInternalReposWithCredentials(connection);
    }

    private static void dropCpeTable(final Connection connection) throws Exception {
        LOGGER.info("Dropping CPE table");
        try (final Statement stmt = connection.createStatement()) {
            stmt.execute("DROP TABLE \"CPE\"");
        }
    }

    private static void authRequiredForInternalReposWithCredentials(final Connection connection) throws Exception {
        LOGGER.info("Marking internal repositories with credentials as \"requires authentication\"");
        try (final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "REPOSITORY"
                SET "AUTHENTICATIONREQUIRED" = ?
                WHERE "INTERNAL" = ? AND ("USERNAME" IS NOT NULL OR "PASSWORD" IS NOT NULL)
                """)) {
            ps.setBoolean(1, true);
            ps.setBoolean(2, true);
            final long updatedRepositories = ps.executeUpdate();
            if (updatedRepositories == 0) {
                LOGGER.info("No repositories had to be updated");
            } else {
                LOGGER.info("Updated %d repositories".formatted(updatedRepositories));
            }
        }
    }

}
