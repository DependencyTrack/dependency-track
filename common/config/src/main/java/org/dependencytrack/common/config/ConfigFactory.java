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
package org.dependencytrack.common.config;

import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigFactory;
import io.smallrye.config.SmallRyeConfigProviderResolver;

/**
 * @since 5.0.0
 */
public final class ConfigFactory extends SmallRyeConfigFactory {

    @Override
    public SmallRyeConfig getConfigFor(
            final SmallRyeConfigProviderResolver configProviderResolver,
            final ClassLoader classLoader) {
        return new SmallRyeConfigBuilder()
                .forClassLoader(classLoader)
                // Enable default config sources:
                //
                // | Source                                               | Priority |
                // | :--------------------------------------------------- | :------- |
                // | System properties                                    | 400      |
                // | Environment variables                                | 300      |
                // | ${pwd}/.env file                                     | 295      |
                // | ${pwd}/config/application.properties                 | 260      |
                // | ${classpath}/application.properties                  | 250      |
                // | ${classpath}/META-INF/microprofile-config.properties | 100      |
                //
                // https://smallrye.io/smallrye-config/Main/config/getting-started/#config-sources
                .addDefaultSources()
                // Enable sources discovered via SPI.
                .addDiscoveredSources()
                // Enable default interceptors for:
                //   * Profile support: https://smallrye.io/smallrye-config/Main/config/profiles/
                //   * Expression support: https://smallrye.io/smallrye-config/Main/config/expressions/
                //   * Secrets support: https://smallrye.io/smallrye-config/Main/config/secret-keys/
                //   * Logging support: https://smallrye.io/smallrye-config/Main/extensions/logging/
                .addDefaultInterceptors()
                // Enable secret key handlers discovered via SPI.
                // https://smallrye.io/smallrye-config/Main/config/secret-keys/
                .addDiscoveredSecretKeysHandlers()
                // Allow applications to customize the Config via SPI.
                // https://smallrye.io/smallrye-config/Main/config/customizer/
                .addDiscoveredCustomizers()
                .build();
    }

}
