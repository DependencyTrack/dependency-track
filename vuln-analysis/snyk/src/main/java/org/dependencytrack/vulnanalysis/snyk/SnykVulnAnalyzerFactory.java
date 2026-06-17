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
package org.dependencytrack.vulnanalysis.snyk;

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

import java.net.URI;
import java.net.http.HttpClient;
import java.util.EnumSet;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class SnykVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable {

    private static final String DEFAULT_API_VERSION = "2025-11-05";

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CacheManager cacheManager;
    private @Nullable HttpClient httpClient;
    private @Nullable ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "snyk";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return SnykVulnAnalyzer.class;
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

        final var config = configRegistry.getRuntimeConfig(SnykVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled");
        }

        final String apiVersion = configRegistry.getDeploymentConfig()
                .getOptionalValue("api-version", String.class)
                .orElse(DEFAULT_API_VERSION);

        return new SnykVulnAnalyzer(
                cacheManager.getCache("results"),
                httpClient,
                objectMapper,
                config.getApiBaseUrl(),
                config.getOrgId(),
                config.getApiToken(),
                apiVersion,
                config.isAliasSyncEnabled());
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(SnykVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new SnykVulnAnalyzerConfigV1()
                        .withEnabled(false)
                        .withApiBaseUrl(URI.create("https://api.snyk.io")),
                config -> {
                    if (!config.isEnabled()) {
                        return;
                    }
                    if (config.getApiBaseUrl() == null) {
                        throw new InvalidRuntimeConfigException("No API base URL provided");
                    }
                    if (config.getOrgId() == null) {
                        throw new InvalidRuntimeConfigException("No organization ID provided");
                    }
                    if (config.getApiToken() == null) {
                        throw new InvalidRuntimeConfigException("No API token provided");
                    }
                });
    }

}
