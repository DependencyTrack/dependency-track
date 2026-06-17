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
package org.dependencytrack.plugin.testing;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * An in-memory {@link MutableConfigRegistry} suitable for testing purposes.
 *
 * @since 5.0.0
 */
public final class MockConfigRegistry implements MutableConfigRegistry {

    private final DeploymentConfig deploymentConfig;
    private final @Nullable RuntimeConfigSpec runtimeConfigSpec;
    private final @Nullable RuntimeConfigMapper runtimeConfigMapper;
    private volatile @Nullable RuntimeConfig runtimeConfig;

    public MockConfigRegistry(
            @Nullable Map<String, String> deploymentConfigs,
            @Nullable RuntimeConfigSpec runtimeConfigSpec,
            @Nullable RuntimeConfigMapper runtimeConfigMapper,
            @Nullable RuntimeConfig runtimeConfig) {
        this.deploymentConfig = new DelegatingDeploymentConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(deploymentConfigs)
                        .build());
        this.runtimeConfigSpec = runtimeConfigSpec;
        this.runtimeConfigMapper = runtimeConfigMapper;
        if (runtimeConfig != null) {
            setRuntimeConfig(runtimeConfig);
        }
    }

    public MockConfigRegistry(Map<String, String> deploymentConfigs) {
        this(deploymentConfigs, null, null, null);
    }

    public MockConfigRegistry(
            @Nullable RuntimeConfigSpec runtimeConfigSpec,
            @Nullable RuntimeConfig runtimeConfig) {
        this(
                Collections.emptyMap(),
                runtimeConfigSpec,
                runtimeConfigSpec != null ? RuntimeConfigMapper.getInstance() : null,
                runtimeConfig);
    }

    public MockConfigRegistry() {
        this(Collections.emptyMap(), null, null, null);
    }

    @Override
    public DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public Optional<@Nullable RuntimeConfig> getOptionalRuntimeConfig() {
        return Optional.ofNullable(runtimeConfig);
    }

    @Override
    public Optional<String> getRawRuntimeConfig() {
        if (runtimeConfig == null || runtimeConfigMapper == null || runtimeConfigSpec == null) {
            return Optional.empty();
        }

        return Optional.of(runtimeConfigMapper.serialize(runtimeConfig));
    }

    @Override
    public boolean setRawRuntimeConfig(String configJson) {
        requireNonNull(runtimeConfigSpec, "runtimeConfigSpec is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(configJson, "configJson must not be null");

        final var configNode = runtimeConfigMapper.validateJson(configJson, runtimeConfigSpec);
        final RuntimeConfig config = runtimeConfigMapper.convert(configNode, runtimeConfigSpec.configClass());
        return setRuntimeConfig(config);
    }

    @Override
    public boolean setRuntimeConfig(RuntimeConfig config) {
        requireNonNull(runtimeConfigSpec, "runtimeConfigSpec is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(config, "runtimeConfig must not be null");

        if (!runtimeConfigSpec.configClass().isInstance(config)) {
            throw new IllegalArgumentException("""
                    The provided config of type %s is not an instance of the \
                    extension's declared config type %s\
                    """.formatted(config.getClass().getName(), runtimeConfigSpec.configClass().getName()));
        }

        runtimeConfigMapper.validate(config, runtimeConfigSpec);

        if (Objects.equals(this.runtimeConfig, config)) {
            return false;
        }

        this.runtimeConfig = config;
        return true;
    }

}
