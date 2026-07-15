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
package org.dependencytrack.vulnanalysis.checkmarx;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;
import java.util.EnumSet;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static java.util.Objects.requireNonNull;

final class CheckmarxVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CacheManager cacheManager;
    private @Nullable HttpClient httpClient;
    private @Nullable ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "checkmarx";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return CheckmarxVulnAnalyzer.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        configRegistry = serviceRegistry.require(ConfigRegistry.class);
        cacheManager = serviceRegistry.require(CacheManager.class);
        httpClient = serviceRegistry.require(HttpClient.class);
        objectMapper = new ObjectMapper()
                .disable(FAIL_ON_UNKNOWN_PROPERTIES);
    }

    @Override
    public VulnAnalyzer create() {
        requireNonNull(configRegistry);
        requireNonNull(cacheManager);
        requireNonNull(httpClient);
        requireNonNull(objectMapper);

        final var config = configRegistry.getRuntimeConfig(CheckmarxVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled");
        }

        final var tokenManager = new CheckmarxAccessTokenManager(httpClient, objectMapper);
        final var apiClient = new CheckmarxApiClient(
                httpClient,
                objectMapper,
                tokenManager,
                config.getRefreshToken(),
                config.getOrgId(),
                config.getAuthApiBaseUrl(),
                config.getApiBaseUrl());

        return new CheckmarxVulnAnalyzer(
                cacheManager.getCache("results"),
                objectMapper,
                apiClient,
                config.isAliasSyncEnabled());
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(CheckmarxVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new CheckmarxVulnAnalyzerConfigV1()
                        .withEnabled(false),
                config -> {
                    if (!config.isEnabled()) {
                        return;
                    }
                    if (config.getAuthApiBaseUrl() == null) {
                        throw new InvalidRuntimeConfigException("No authentication API base URL provided");
                    }
                    if (config.getApiBaseUrl() == null) {
                        throw new InvalidRuntimeConfigException("No API base URL provided");
                    }
                    if (config.getRefreshToken() == null) {
                        throw new InvalidRuntimeConfigException("No Refresh Token provided");
                    }
                    if (config.getOrgId() == null) {
                        throw new InvalidRuntimeConfigException("No Organization ID provided");
                    }
                });
    }

}

