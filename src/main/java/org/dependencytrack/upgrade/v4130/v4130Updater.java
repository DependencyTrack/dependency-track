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
package org.dependencytrack.upgrade.v4130;

import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;

public class v4130Updater extends AbstractUpgradeItem {

    @Override
    public String getSchemaVersion() {
        return "4.13.0";
    }

    @Override
    public boolean shouldUpgrade(final AlpineQueryManager qm, final Connection connection) {
        return false; // Revised upgrade logic moved to v4130_1Updater.
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        // Revised upgrade logic moved to v4130_1Updater.
    }

}
