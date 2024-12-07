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
package org.dependencytrack.upgrade;

import alpine.server.upgrade.UpgradeItem;

import java.util.ArrayList;
import java.util.List;

class UpgradeItems {

    private static final List<Class<? extends UpgradeItem>> UPGRADE_ITEMS = new ArrayList<>();
    static {
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v400.v400Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v410.v410Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v420.v420Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v440.v440Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v450.v450Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v460.v460Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v463.v463Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v470.v470Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v480.v480Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v490.v490Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v4100.v4100Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v4110.v4110Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v4120.v4120Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v4122.v4122Updater.class);
        UPGRADE_ITEMS.add(org.dependencytrack.upgrade.v4130.v4130Updater.class);
    }

    static List<Class<? extends UpgradeItem>> getUpgradeItems() {
        return UPGRADE_ITEMS;
    }

}
