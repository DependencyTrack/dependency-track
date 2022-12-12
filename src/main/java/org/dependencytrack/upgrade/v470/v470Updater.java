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
package org.dependencytrack.upgrade.v470;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;

import static org.dependencytrack.model.ConfigPropertyConstants.TASK_SCHEDULER_COMPONENT_ANALYSIS_CACHE_CLEAR_CADENCE;

public class v470Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v470Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.7.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        LOGGER.info("Setting component analysis cache clear cadence to 24H");
        final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "CONFIGPROPERTY" SET "PROPERTYVALUE" = ?
                WHERE "GROUPNAME" = ? AND "PROPERTYNAME" = ?
                """);
        ps.setString(1, TASK_SCHEDULER_COMPONENT_ANALYSIS_CACHE_CLEAR_CADENCE.getDefaultPropertyValue());
        ps.setString(2, TASK_SCHEDULER_COMPONENT_ANALYSIS_CACHE_CLEAR_CADENCE.getGroupName());
        ps.setString(3, TASK_SCHEDULER_COMPONENT_ANALYSIS_CACHE_CLEAR_CADENCE.getPropertyName());
        ps.executeUpdate();
    }

}
