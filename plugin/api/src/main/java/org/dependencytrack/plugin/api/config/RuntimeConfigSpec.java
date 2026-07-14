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

import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class RuntimeConfigSpec {

    private final Class<? extends RuntimeConfig> configClass;
    @SuppressWarnings("rawtypes")
    private final @Nullable RuntimeConfigValidator validator;
    private final RuntimeConfig defaultConfig;
    private final String schema;

    @SuppressWarnings("rawtypes")
    private RuntimeConfigSpec(
            RuntimeConfig defaultConfig,
            @Nullable RuntimeConfigSchemaSource schemaSource,
            @Nullable RuntimeConfigValidator validator) {
        this.defaultConfig = requireNonNull(defaultConfig, "defaultConfig must not be null");
        this.configClass = defaultConfig.getClass();
        this.schema = loadSchema(configClass, schemaSource);
        this.validator = validator;
    }

    public static <T extends RuntimeConfig> RuntimeConfigSpec of(
            T defaultConfig,
            @Nullable RuntimeConfigSchemaSource schemaSource,
            @Nullable RuntimeConfigValidator<T> validator) {
        return new RuntimeConfigSpec(defaultConfig, schemaSource, validator);
    }

    public static <T extends RuntimeConfig> RuntimeConfigSpec of(T defaultConfig, RuntimeConfigValidator<T> validator) {
        return new RuntimeConfigSpec(defaultConfig, null, validator);
    }

    public static <T extends RuntimeConfig> RuntimeConfigSpec of(T defaultConfig) {
        return new RuntimeConfigSpec(defaultConfig, null, null);
    }

    public Class<? extends RuntimeConfig> configClass() {
        return configClass;
    }

    @SuppressWarnings("rawtypes")
    public @Nullable RuntimeConfigValidator validator() {
        return validator;
    }

    public RuntimeConfig defaultConfig() {
        return defaultConfig;
    }

    public String schema() {
        return schema;
    }

    private static String loadSchema(
            Class<? extends RuntimeConfig> configClass,
            @Nullable RuntimeConfigSchemaSource schemaSource) {
        final String schema;
        if (schemaSource != null) {
            schema = schemaSource.getSchema(configClass);
        } else {
            final String configClassNameKebab = configClass.getSimpleName()
                    .replaceAll("([a-z])([A-Z])", "$1-$2")
                    .toLowerCase();

            final String schemaFileName = configClassNameKebab + ".schema.json";
            schema = new RuntimeConfigSchemaSource.Resource(schemaFileName).getSchema(configClass);
        }

        return requireNonNull(schema, "schema must not be null");
    }

}
