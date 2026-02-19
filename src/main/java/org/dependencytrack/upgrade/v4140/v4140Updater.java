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
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class v4140Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4140Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.14.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        resetGhsaLastModifiedTimestamp(connection);
    }

    /**
     * Resets the GitHub Advisories last-modified epoch timestamp to force a full re-mirror on next run.
     * <p>
     * This is necessary to backfill EPSS scores on existing GHSA vulnerability entries. The normal
     * mirror update path is skipped when an advisory's {@code updatedAt} has not changed, but EPSS
     * data is now available for advisories that were previously mirrored without it.
     */
    private void resetGhsaLastModifiedTimestamp(final Connection connection) throws SQLException {
        LOGGER.info("Resetting GitHub Advisories last-modified timestamp to trigger full re-mirror for EPSS backfill");
        try (final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "CONFIGPROPERTY"
                   SET "PROPERTYVALUE" = NULL
                 WHERE "GROUPNAME" = 'vuln-source'
                   AND "PROPERTYNAME" = 'github.advisories.last.modified.epoch.seconds'
                """)) {
            final int rows = ps.executeUpdate();
            LOGGER.info("Reset last-modified timestamp (%d row(s) affected)".formatted(rows));
        }
    }
}
