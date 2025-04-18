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

import alpine.server.upgrade.UpgradeMetaProcessor;

import java.sql.Connection;

/**
 * @since 4.13.0
 */
public interface PreUpgradeHook {

    /**
     * @return The order in which the hook shall be executed. Hooks are executed from lowest to highest order.
     * The order must be unique across all {@link PreUpgradeHook}s to ensure proper execution order,
     * even when users upgrade from very old version.
     */
    int order();

    boolean shouldExecute(final UpgradeMetaProcessor upgradeProcessor);

    void execute(final Connection connection) throws Exception;

}
