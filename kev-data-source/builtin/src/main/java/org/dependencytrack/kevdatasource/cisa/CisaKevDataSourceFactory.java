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
package org.dependencytrack.kevdatasource.cisa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.http.HttpClient;

import static java.util.Objects.requireNonNull;

/// @since 5.1.0
public final class CisaKevDataSourceFactory implements KevDataSourceFactory, RuntimeConfigurable {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable HttpClient httpClient;
    private @Nullable ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "cisa";
    }

    @Override
    public Class<? extends KevDataSource> extensionClass() {
        return CisaKevDataSource.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST + 100;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig =
                new CisaKevDataSourceConfigV1()
                        .withEnabled(true)
                        .withFeedUrl(URI.create("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"));

        return RuntimeConfigSpec.of(defaultConfig, config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getFeedUrl() == null) {
                throw new InvalidRuntimeConfigException("No feed URL provided");
            }
        });
    }

    @Override
    public boolean isEnabled() {
        return requireNonNull(configRegistry)
                .getRuntimeConfig(CisaKevDataSourceConfigV1.class)
                .isEnabled();
    }

    @Override
    public KevDataSource create() {
        final var config = requireNonNull(configRegistry)
                .getRuntimeConfig(CisaKevDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("KEV data source is disabled and cannot be created");
        }

        return new CisaKevDataSource(
                requireNonNull(httpClient),
                requireNonNull(objectMapper),
                config.getFeedUrl());
    }

}
