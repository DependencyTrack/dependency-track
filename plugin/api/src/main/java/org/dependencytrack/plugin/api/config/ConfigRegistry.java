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
package org.dependencytrack.plugin.api.config;

import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * A read-only registry for accessing application configuration.
 *
 * @since 5.0.0
 */
public interface ConfigRegistry {

    /**
     * Retrieve the deployment config.
     *
     * @return The deployment config.
     * @since 5.0.0
     */
    DeploymentConfig getDeploymentConfig();

    /**
     * Retrieve the runtime config.
     *
     * @return The runtime config.
     * @since 5.0.0
     */
    Optional<RuntimeConfig> getOptionalRuntimeConfig();

    /**
     * Retrieve the runtime config.
     *
     * @param configClass Class of the runtime config.
     * @param <T>         Type of the runtime config.
     * @return The runtime config.
     * @throws ClassCastException When the config object can not be cast to the provided {@code configClass}.
     * @see #getOptionalRuntimeConfig()
     * @since 5.0.0
     */
    default <T extends RuntimeConfig> Optional<T> getOptionalRuntimeConfig(Class<T> configClass) {
        return getOptionalRuntimeConfig().map(configClass::cast);
    }

    /**
     * Retrieve the runtime config, throwing if it doesn't exist.
     *
     * @param configClass Class of the runtime config.
     * @param <T>         Type of the runtime config.
     * @return The runtime config.
     * @throws NoSuchElementException When no runtime config exists.
     * @see #getOptionalRuntimeConfig(Class)
     * @since 5.0.0
     */
    default <T extends RuntimeConfig> T getRuntimeConfig(Class<T> configClass) {
        return getOptionalRuntimeConfig()
                .map(configClass::cast)
                .orElseThrow(() -> new NoSuchElementException("No runtime config found"));
    }

}
