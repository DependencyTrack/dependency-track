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

import java.util.Optional;

/**
 * A {@link ConfigRegistry} that supports runtime config modification.
 *
 * @since 5.0.0
 */
public interface MutableConfigRegistry extends ConfigRegistry {

    /**
     * @param config The config to set.
     * @return {@code true} when the config was updated, {@code false} when it wasn't.
     * @throws IllegalStateException    When the extension does not support runtime configuration.
     * @throws IllegalArgumentException When the given config doesn't match the expected type.
     */
    boolean setRuntimeConfig(RuntimeConfig config);

    /**
     * @return The raw JSON runtime config, if present.
     */
    Optional<String> getRawRuntimeConfig();

    /**
     * @param configJson The raw JSON config to persist.
     * @return {@code true} when the config was updated, {@code false} when it wasn't.
     */
    boolean setRawRuntimeConfig(String configJson);

}
