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
package org.dependencytrack.upgrade.v4120;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class v4120Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4120Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.12.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        removeExperimentalBomUploadProcessingV2ConfigProperty(connection);
    }

    private static void removeExperimentalBomUploadProcessingV2ConfigProperty(final Connection connection) throws SQLException {
        final var propertyGroup = "experimental";
        final var propertyName = "bom.processing.task.v2.enabled";

        LOGGER.info("Removing ConfigProperty %s:%s".formatted(propertyGroup, propertyName));

        try (final PreparedStatement ps = connection.prepareStatement("""
                DELETE
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = ?
                   AND "PROPERTYNAME" = ?
                """)) {
            ps.setString(1, propertyGroup);
            ps.setString(2, propertyName);
            ps.executeUpdate();
        }
    }

}
