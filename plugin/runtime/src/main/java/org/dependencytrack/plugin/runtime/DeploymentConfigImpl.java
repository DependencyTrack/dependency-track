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

import org.dependencytrack.common.config.NamespacedConfig;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.eclipse.microprofile.config.Config;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class DeploymentConfigImpl implements DeploymentConfig {

    private final Config delegate;

    DeploymentConfigImpl(
            Config delegate,
            String extensionPointName,
            String extensionName) {
        requireNonNull(extensionPointName, "extensionPointName must not be null");
        requireNonNull(extensionName, "extensionName must not be null");
        this.delegate = new NamespacedConfig(delegate, "dt.%s.%s".formatted(extensionPointName, extensionName));
    }

    @Override
    public <T> T getValue(String propertyName, Class<T> propertyType) {
        return delegate.getValue(propertyName, propertyType);
    }

    @Override
    public <T> Optional<T> getOptionalValue(String propertyName, Class<T> propertyType) {
        return delegate.getOptionalValue(propertyName, propertyType);
    }

}
