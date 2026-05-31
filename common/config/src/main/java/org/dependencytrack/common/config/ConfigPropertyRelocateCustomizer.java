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

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.Priorities;
import io.smallrye.config.RelocateConfigSourceInterceptor;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigBuilderCustomizer;

import java.util.OptionalInt;

import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_LOG_VALUES;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_PROFILE;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_PROFILE_PARENT;

/**
 * @since 5.0.0
 */
public final class ConfigPropertyRelocateCustomizer implements SmallRyeConfigBuilderCustomizer {

    @Override
    public void configBuilder(SmallRyeConfigBuilder builder) {
        builder.withInterceptorFactories(new ConfigSourceInterceptorFactory() {

            @Override
            public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
                return new RelocateConfigSourceInterceptor(name -> switch (name) {
                    case SMALLRYE_CONFIG_LOG_VALUES -> "dt.config.log-values";
                    case SMALLRYE_CONFIG_PROFILE -> "dt.config.profile";
                    case SMALLRYE_CONFIG_PROFILE_PARENT -> "dt.config.profile.parent";
                    default -> name;
                });
            }

            @Override
            public OptionalInt getPriority() {
                // NB: Must be just below ProfileConfigSourceInterceptor (LIBRARY + 200).
                return OptionalInt.of(Priorities.LIBRARY + 200 - 10);
            }

        });
    }

}
