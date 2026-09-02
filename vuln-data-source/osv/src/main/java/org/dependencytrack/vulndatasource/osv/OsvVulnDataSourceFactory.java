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
package org.dependencytrack.vulndatasource.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class OsvVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable {

    private static final String DEFAULT_SOURCE_NAME = "default";
    private @Nullable ConfigRegistry configRegistry;
    private @Nullable KeyValueStore kvStore;
    private @Nullable ObjectMapper objectMapper;
    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "osv";
    }

    @Override
    public String displayName() {
        return "OSV";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return OsvVulnDataSource.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST + 100;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.kvStore = serviceRegistry.require(KeyValueStore.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultSource = new OsvSourceConfigV1()
                .withName(DEFAULT_SOURCE_NAME)
                .withIncrementalMirroringEnabled(true)
                .withEnabled(false)
                .withAliasSyncEnabled(false)
                .withDataUrl(URI.create("https://storage.googleapis.com/osv-vulnerabilities"))
                .withEcosystems(Set.of("Go", "Maven", "npm", "NuGet", "PyPI"));

        final var defaultConfig =
                new OsvVulnDataSourceConfigV1().withSources(new LinkedHashSet<>(Set.of(defaultSource)));

        return RuntimeConfigSpec.of(defaultConfig, (OsvVulnDataSourceConfigV1 config) -> {
            for (final var source : config.getSources()) {
                if (source.getName() == null || source.getName().isBlank()) {
                    throw new InvalidRuntimeConfigException("No data source name provided");
                }
                if (!source.isEnabled()) {
                    continue;
                }
                if (source.getDataUrl() == null) {
                    throw new InvalidRuntimeConfigException("No data URL provided");
                }
                if (source.getEcosystems() == null || source.getEcosystems().isEmpty()) {
                    throw new InvalidRuntimeConfigException("At least one ecosystem must be specified");
                }
            }
        });
    }

    @Override
    public boolean isDataSourceEnabled() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        return !enabledSources(configRegistry.getRuntimeConfig(OsvVulnDataSourceConfigV1.class))
                .isEmpty();
    }

    @Override
    public VulnDataSource create() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(kvStore, "kvStore must not be null");
        requireNonNull(objectMapper, "objectMapper must not be null");
        requireNonNull(httpClient, "httpClient must not be null");

        final List<OsvSourceConfigV1> sources =
                enabledSources(configRegistry.getRuntimeConfig(OsvVulnDataSourceConfigV1.class));
        if (sources.isEmpty()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final var dataSources = new ArrayList<OsvVulnDataSource>(sources.size());
        for (final OsvSourceConfigV1 source : sources) {
            final WatermarkManager watermarkManager = source.isIncrementalMirroringEnabled()
                    ? new WatermarkManager(source.getName(), source.getEcosystems(), kvStore)
                    : null;

            dataSources.add(new OsvVulnDataSource(
                    source.getName(),
                    watermarkManager,
                    objectMapper,
                    source.getDataUrl().toString(),
                    source.getEcosystems(),
                    httpClient,
                    source.getAliasSyncEnabled()));
        }
        return new OsvCompositeVulnDataSource(dataSources);
    }

    private List<OsvSourceConfigV1> enabledSources(final OsvVulnDataSourceConfigV1 config) {
        return config.getSources().stream().filter(OsvSourceConfigV1::isEnabled).toList();
    }
}
