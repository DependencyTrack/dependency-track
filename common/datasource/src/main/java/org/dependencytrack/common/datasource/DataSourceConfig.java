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
package org.dependencytrack.common.datasource;

import org.eclipse.microprofile.config.Config;

import java.nio.file.Path;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class DataSourceConfig {

    private static final String PREFIX = "dt.datasource.";

    private final Config config;
    private final String name;

    DataSourceConfig(final Config config, final String name) {
        this.config = requireNonNull(config, "config must not be null");
        this.name = requireNonNull(name, "name must not be null");
    }

    String getName() {
        return name;
    }

    String getUrl() {
        return config.getValue(PREFIX + "%s.url".formatted(name), String.class);
    }

    Optional<String> getUsername() {
        return config.getOptionalValue(PREFIX + "%s.username".formatted(name), String.class);
    }

    Optional<String> getPassword() {
        return config.getOptionalValue(PREFIX + "%s.password".formatted(name), String.class);
    }

    Optional<Path> getPasswordFilePath() {
        return config.getOptionalValue(PREFIX + "%s.password-file".formatted(name), Path.class);
    }

    Optional<Long> getConnectionTimeoutMillis() {
        return config.getOptionalValue(PREFIX + "%s.connection-timeout-ms".formatted(name), long.class);
    }

    boolean isPoolEnabled() {
        return config.getOptionalValue(PREFIX + "%s.pool.enabled".formatted(name), boolean.class).orElse(false);
    }

    int getPoolMaxSize() {
        return config.getValue(PREFIX + "%s.pool.max-size".formatted(name), int.class);
    }

    int getPoolMinIdle() {
        return config.getValue(PREFIX + "%s.pool.min-idle".formatted(name), int.class);
    }

    Optional<Long> getPoolIdleTimeoutMillis() {
        return config.getOptionalValue(PREFIX + "%s.pool.idle-timeout-ms".formatted(name), long.class);
    }

    Optional<Long> getPoolMaxLifetimeMillis() {
        return config.getOptionalValue(PREFIX + "%s.pool.max-lifetime-ms".formatted(name), long.class);
    }

    Optional<Long> getPoolKeepaliveIntervalMillis() {
        return config.getOptionalValue(PREFIX + "%s.pool.keepalive-interval-ms".formatted(name), long.class);
    }

}
