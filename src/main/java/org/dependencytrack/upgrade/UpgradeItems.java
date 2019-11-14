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
package org.dependencytrack.upgrade;

import alpine.upgrade.UpgradeItem;
import java.util.ArrayList;
import java.util.List;

class UpgradeItems {

    private static final List<Class<? extends UpgradeItem>> UPGRADE_ITEMS = new ArrayList<>();
    static {
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v310.v310Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v320.v320Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v321.v321Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v330.v330Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v340.v340Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v350.v350Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v360.v360Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v370.v370Updater.class);
    };

    static List<Class<? extends UpgradeItem>> getUpgradeItems() {
        return UPGRADE_ITEMS;
    }

}
