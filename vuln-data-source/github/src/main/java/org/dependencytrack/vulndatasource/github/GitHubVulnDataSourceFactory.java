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
package org.dependencytrack.vulndatasource.github;

import io.github.jeremylong.openvulnerability.client.HttpAsyncClientSupplier;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;

/**
 * @since 5.0.0
 */
final class GitHubVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable {

    private ConfigRegistry configRegistry;
    private KeyValueStore kvStore;
    private HttpAsyncClientSupplier httpClientSupplier;

    @Override
    public String extensionName() {
        return "github";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return GitHubVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.kvStore = serviceRegistry.require(KeyValueStore.class);
        final var proxySelector = serviceRegistry.require(HttpClient.class).proxy().orElse(null);
        this.httpClientSupplier = () -> HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .setProxySelector(proxySelector)
                .build();
    }

    @Override
    public boolean isDataSourceEnabled() {
        return configRegistry.getRuntimeConfig(GithubVulnDataSourceConfigV1.class).isEnabled();
    }

    @Override
    public VulnDataSource create() {
        final var config = configRegistry.getRuntimeConfig(GithubVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), this.kvStore);

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientSupplier)
                .withEndpoint(config.getApiUrl().toString())
                .withApiKey(config.getApiToken());
        if (watermarkManager.getWatermark() != null) {
            clientBuilder.withUpdatedSinceFilter(
                    ZonedDateTime.ofInstant(watermarkManager.getWatermark(), ZoneOffset.UTC));
        }
        final GitHubSecurityAdvisoryClient client = clientBuilder.build();

        return new GitHubVulnDataSource(watermarkManager, client, config.getAliasSyncEnabled());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new GithubVulnDataSourceConfigV1()
                .withEnabled(false)
                .withAliasSyncEnabled(true)
                .withApiUrl(URI.create("https://api.github.com/graphql"));

        return RuntimeConfigSpec.of(defaultConfig, config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getApiUrl() == null) {
                throw new InvalidRuntimeConfigException("No API URL provided");
            }
            if (config.getApiToken() == null) {
                throw new InvalidRuntimeConfigException("No API Token provided");
            }
        });
    }

}
