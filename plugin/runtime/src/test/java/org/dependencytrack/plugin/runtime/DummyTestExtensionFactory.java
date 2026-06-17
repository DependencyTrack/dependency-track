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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.jspecify.annotations.NonNull;

class DummyTestExtensionFactory implements ExtensionFactory<@NonNull TestExtensionPoint> {

    private ConfigRegistry configRegistry;

    @Override
    public @NonNull String extensionName() {
        return DummyTestExtension.NAME;
    }

    @Override
    public @NonNull Class<? extends TestExtensionPoint> extensionClass() {
        return DummyTestExtension.class;
    }

    @Override
    public int priority() {
        return PRIORITY_LOWEST;
    }

    @Override
    public void init(@NonNull ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
    }

    @Override
    public DummyTestExtension create() {
        return new DummyTestExtension(configRegistry.getDeploymentConfig().getOptionalValue("bar", String.class).orElse(null));
    }

}
