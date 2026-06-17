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
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoggingConfigurationTest {

    private LoggerContext loggerContext;

    @BeforeEach
    void beforeEach() {
        loggerContext = new LoggerContext();
    }

    @Test
    void shouldApplyPerLoggerOverride() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.logging.level.\"org.dependencytrack\"", "TRACE")
                .withDefaultValue("dt.logging.level.\"org.eclipse.jetty\"", "ERROR")
                .build();

        new LoggingConfiguration(config).apply(loggerContext);

        assertThat(loggerContext.getLogger("org.dependencytrack").getLevel()).isEqualTo(Level.TRACE);
        assertThat(loggerContext.getLogger("org.eclipse.jetty").getLevel()).isEqualTo(Level.ERROR);
    }

    @Test
    void shouldApplyRootLoggerOverride() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.logging.level.\"ROOT\"", "ERROR")
                .build();

        new LoggingConfiguration(config).apply(loggerContext);

        assertThat(loggerContext.getLogger("ROOT").getLevel()).isEqualTo(Level.ERROR);
    }

    @Test
    void shouldNotChangeLevelsWhenNoConfigProvided() {
        final Config config = new SmallRyeConfigBuilder().build();

        new LoggingConfiguration(config).apply(loggerContext);

        assertThat(loggerContext.getLogger("org.dependencytrack").getLevel()).isNull();
    }

}
