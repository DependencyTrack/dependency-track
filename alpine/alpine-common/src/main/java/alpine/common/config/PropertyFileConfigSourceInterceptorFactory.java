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

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Properties;

/**
 * A {@link ConfigSourceInterceptorFactory} that redirects property resolution to specific properties files.
 *
 * @since 5.0.0
 */
final class PropertyFileConfigSourceInterceptorFactory implements ConfigSourceInterceptorFactory {

    private final String name;
    private final Properties properties;
    private final Map<String, String> propertyNameMappings;

    PropertyFileConfigSourceInterceptorFactory(
            final URL propertyFileUrl,
            final Map<String, String> propertyNameMappings) {
        this.name = "%s[source=%s]".formatted(getClass().getSimpleName(), propertyFileUrl);
        this.properties = loadPropertiesFromFile(propertyFileUrl);
        this.propertyNameMappings = propertyNameMappings;
    }

    @Override
    public ConfigSourceInterceptor getInterceptor(final ConfigSourceInterceptorContext context) {
        return (ctx, name) -> {
            if (properties == null) {
                return ctx.proceed(name);
            }

            final String mappedName = propertyNameMappings.get(name);
            if (mappedName == null) {
                return ctx.proceed(name);
            }

            final Object value = properties.get(mappedName);
            if (value == null) {
                return null;
            }

            return ConfigValue.builder()
                    .withName(name)
                    .withValue(String.valueOf(value))
                    .withRawValue(String.valueOf(value))
                    .withConfigSourceName(this.name)
                    .build();
        };
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(Integer.MAX_VALUE);
    }

    private static Properties loadPropertiesFromFile(final URL fileUrl) {
        if (fileUrl == null) {
            return null;
        }

        final var properties = new Properties();
        try (final InputStream fileInputStream = fileUrl.openStream()) {
            properties.load(fileInputStream);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load property file", e);
        }

        return properties;
    }

}
