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
package org.dependencytrack.upgrade.v490;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;
import java.sql.Connection;
import java.sql.PreparedStatement;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_VERSION;

public class v490Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v490Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.9.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        updateDefaultSnykApiVersion(connection);
        removeUnstableVersionsFromAnalysisCacheAndRepoMetadata(connection);
    }

    /**
     * Update the Snyk API version from its previous default to a current and actively supported one.
     * Only do so when the version has not been modified manually.
     *
     * @param connection The {@link Connection} to use for executing queries
     * @throws Exception When executing a query failed
     */
    private static void updateDefaultSnykApiVersion(final Connection connection) throws Exception {
        LOGGER.info("Updating Snyk API version from 2022-11-14 to %s"
                .formatted(SCANNER_SNYK_API_VERSION.getDefaultPropertyValue()));
        try (final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "CONFIGPROPERTY" SET "PROPERTYVALUE" = ?
                WHERE "GROUPNAME" = 'scanner'
                    AND "PROPERTYNAME" = 'snyk.api.version'
                    AND "PROPERTYVALUE" = '2022-11-14'
                """)) {
            ps.setString(1, SCANNER_SNYK_API_VERSION.getDefaultPropertyValue());
            ps.executeUpdate();
        }
    }

    /**
     * Versions with a '-' in it probably indicate unstable versions. Remove them all
     * from component analysis cache and repository metadata, so only stable versions
     * remain.
     *
     * @param connection The {@link Connection} to use for executing queries
     * @throws Exception When executing a query failed
     * @see: https://github.com/DependencyTrack/dependency-track/issues/2500
     */
    private void removeUnstableVersionsFromAnalysisCacheAndRepoMetadata(Connection connection) throws Exception {
        LOGGER.info("Removing possible unstable versions from component analysis cache");
        DbUtil.executeUpdate(connection, "DELETE FROM \"COMPONENTANALYSISCACHE\" WHERE RESULT LIKE '%-%'");
        LOGGER.info("Removing possible unstable versions from repository metadata");
        DbUtil.executeUpdate(connection, "DELETE FROM \"REPOSITORY_META_COMPONENT\" WHERE LATEST_VERSION LIKE '%-%'");
    }

}
