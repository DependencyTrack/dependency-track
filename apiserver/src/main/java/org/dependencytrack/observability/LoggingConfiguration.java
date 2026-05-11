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
package org.dependencytrack.observability;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import io.smallrye.config.SmallRyeConfig;
import org.eclipse.microprofile.config.Config;

/**
 * @since 5.0.0
 */
public final class LoggingConfiguration {

    private final Config config;

    public LoggingConfiguration(Config config) {
        this.config = config;
    }

    public void apply(LoggerContext loggerContext) {
        final var smallRyeConfig = config.unwrap(SmallRyeConfig.class);
        for (final var entry : smallRyeConfig.getMapKeys("dt.logging.level").entrySet()) {
            final String loggerName = entry.getKey();
            final var level = Level.toLevel(config.getValue(entry.getValue(), String.class));

            loggerContext.getLogger(loggerName).setLevel(level);
        }
    }

}
