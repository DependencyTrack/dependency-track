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
package org.dependencytrack.plugin.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.eclipse.microprofile.config.Config;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class ConfigRegistryImpl implements MutableConfigRegistry {

    private final Jdbi jdbi;
    private final String extensionPointName;
    private final String extensionName;
    private final DeploymentConfig deploymentConfig;
    private final @Nullable RuntimeConfigSpec runtimeConfigSpec;
    private final @Nullable RuntimeConfigMapper runtimeConfigMapper;
    private final @Nullable Function<String, @Nullable String> secretResolver;

    ConfigRegistryImpl(
            Jdbi jdbi,
            Config config,
            String extensionPointName,
            String extensionName,
            @Nullable RuntimeConfigSpec runtimeConfigSpec,
            @Nullable RuntimeConfigMapper runtimeConfigMapper,
            @Nullable Function<String, @Nullable String> secretResolver) {
        this.jdbi = requireNonNull(jdbi, "jdbi must not be null");
        this.extensionPointName = requireNonNull(extensionPointName, "extensionPointName must not be null");
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");
        this.deploymentConfig = new DeploymentConfigImpl(config, extensionPointName, extensionName);
        this.runtimeConfigSpec = runtimeConfigSpec;
        this.runtimeConfigMapper = runtimeConfigMapper;
        this.secretResolver = secretResolver;
    }

    @Override
    public DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public Optional<RuntimeConfig> getOptionalRuntimeConfig() {
        if (runtimeConfigSpec == null) {
            return Optional.empty();
        }
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(secretResolver, "secretResolver is not initialized");

        final String configJson = jdbi.withHandle(
                handle -> new ExtensionConfigDao(handle).get(
                        extensionPointName, extensionName));
        if (configJson == null) {
            return Optional.empty();
        }

        final JsonNode configJsonNode = runtimeConfigMapper.validateJson(configJson, runtimeConfigSpec);

        runtimeConfigMapper.resolveSecretRefs(configJsonNode, runtimeConfigSpec, secretResolver);

        final RuntimeConfig runtimeConfig = runtimeConfigMapper.convert(configJsonNode, runtimeConfigSpec.configClass());

        if (runtimeConfigSpec.validator() != null) {
            runtimeConfigSpec.validator().validate(runtimeConfig);
        }

        return Optional.of(runtimeConfig);
    }

    @Override
    public boolean setRuntimeConfig(RuntimeConfig config) {
        requireNonNull(runtimeConfigSpec, "runtimeConfigSpec is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(config, "config must not be null");

        if (!runtimeConfigSpec.configClass().isInstance(config)) {
            throw new IllegalArgumentException("""
                    The provided config of type %s is not an instance of the \
                    extension's declared config type %s\
                    """.formatted(config.getClass().getName(), runtimeConfigSpec.configClass().getName()));
        }

        runtimeConfigMapper.validate(config, runtimeConfigSpec);

        final String configJson = runtimeConfigMapper.serialize(config);

        return jdbi.inTransaction(
                handle -> new ExtensionConfigDao(handle).save(
                        extensionPointName, extensionName, configJson));
    }

    @Override
    public Optional<String> getRawRuntimeConfig() {
        return Optional.ofNullable(
                jdbi.withHandle(
                        handle -> new ExtensionConfigDao(handle).get(
                                extensionPointName, extensionName)));
    }

    @Override
    public boolean setRawRuntimeConfig(String configJson) {
        requireNonNull(configJson, "configJson must not be null");

        return jdbi.inTransaction(
                handle -> new ExtensionConfigDao(handle).save(
                        extensionPointName, extensionName, configJson));
    }

    boolean hasRuntimeConfig() {
        if (runtimeConfigSpec == null) {
            return false;
        }

        return jdbi.withHandle(
                handle -> new ExtensionConfigDao(handle).exists(
                        extensionPointName, extensionName));
    }

}
