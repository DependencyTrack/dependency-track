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
package org.dependencytrack.vulnanalysis.trivy;

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

import static java.util.Objects.requireNonNull;

final class TrivyVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "trivy";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return TrivyVulnAnalyzer.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        configRegistry = serviceRegistry.require(ConfigRegistry.class);
        httpClient = serviceRegistry.require(HttpClient.class);
    }

    @Override
    public VulnAnalyzer create() {
        requireNonNull(configRegistry);
        requireNonNull(httpClient);

        final var config = configRegistry.getRuntimeConfig(TrivyVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled");
        }

        return new TrivyVulnAnalyzer(
                httpClient,
                config.getApiUrl().toString(),
                config.getApiToken(),
                config.isIgnoreUnfixed(),
                config.isScanLibrary(),
                config.isScanOs());
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(TrivyVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_TYPE,
                VulnAnalyzerRequirement.COMPONENT_PROPERTIES);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new TrivyVulnAnalyzerConfigV1()
                        .withEnabled(false)
                        .withIgnoreUnfixed(false)
                        .withScanLibrary(true)
                        .withScanOs(false),
                config -> {
                    if (!config.isEnabled()) {
                        return;
                    }
                    if (config.getApiUrl() == null) {
                        throw new InvalidRuntimeConfigException("No API URL provided");
                    }
                    if (config.getApiToken() == null) {
                        throw new InvalidRuntimeConfigException("No API token provided");
                    }
                });
    }

}
