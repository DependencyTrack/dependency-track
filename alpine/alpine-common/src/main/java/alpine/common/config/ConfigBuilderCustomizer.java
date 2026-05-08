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
package alpine.common.config;

import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigBuilderCustomizer;

import java.util.Map;

/**
 * @since 5.0.0
 */
public final class ConfigBuilderCustomizer implements SmallRyeConfigBuilderCustomizer {

    @Override
    public void configBuilder(final SmallRyeConfigBuilder builder) {
        // Default values for alpine framework properties live in
        // META-INF/microprofile-config.properties (ordinal 100), which apiserver's
        // application.properties (ordinal 250) overrides where it differs.
        // Always redirect Alpine build info properties to the respective
        // alpine.version and application.version property files.
        builder.withInterceptorFactories(
                new PropertyFileConfigSourceInterceptorFactory(
                        Thread.currentThread().getContextClassLoader().getResource("alpine.version"),
                        Map.ofEntries(
                                Map.entry("alpine.build-info.framework.name", "name"),
                                Map.entry("alpine.build-info.framework.version", "version"),
                                Map.entry("alpine.build-info.framework.uuid", "uuid"),
                                Map.entry("alpine.build-info.framework.timestamp", "timestamp"))),
                new PropertyFileConfigSourceInterceptorFactory(
                        Thread.currentThread().getContextClassLoader().getResource("application.version"),
                        Map.ofEntries(
                                Map.entry("alpine.build-info.application.name", "name"),
                                Map.entry("alpine.build-info.application.version", "version"),
                                Map.entry("alpine.build-info.application.uuid", "uuid"),
                                Map.entry("alpine.build-info.application.timestamp", "timestamp"))));
    }

}
