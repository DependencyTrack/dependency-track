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
package org.dependencytrack.cache.api;

import org.eclipse.microprofile.config.Config;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class CacheConfig {

    private final Config config;
    private final String name;

    public CacheConfig(Config config, String name) {
        this.config = requireNonNull(config, "config must not be null");
        this.name = requireNonNull(name, "name must not be null");
    }

    public Duration ttl() {
        return config
                .getOptionalValue("dt.cache.\"%s\".ttl-ms".formatted(this.name), long.class)
                .map(Duration::ofMillis)
                .orElse(Duration.ofHours(1));
    }

}
