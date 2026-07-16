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
import org.jspecify.annotations.Nullable;

import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class GitHubVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable KeyValueStore kvStore;
    private @Nullable HttpClient httpClient;
    private @Nullable ProxySelector proxySelector;

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
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.proxySelector = httpClient.proxy().orElse(null);
    }

    @Override
    public boolean isDataSourceEnabled() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        return configRegistry.getRuntimeConfig(GithubVulnDataSourceConfigV1.class).isEnabled();
    }

    @Override
    public VulnDataSource create() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(kvStore, "kvStore must not be null");

        final var config = configRegistry.getRuntimeConfig(GithubVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), this.kvStore);

        final GitHubTokenProvider tokenProvider = createTokenProvider(config);
        final HttpAsyncClientSupplier httpClientSupplier = () -> HttpAsyncClients.custom()
                .setRetryStrategy(new GitHubHttpRequestRetryStrategy())
                .setProxySelector(proxySelector)
                .addRequestInterceptorFirst(new BearerTokenInterceptor(tokenProvider))
                .build();

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientSupplier)
                .withEndpoint(config.getApiUrl().toString());
        if (watermarkManager.getWatermark() != null) {
            clientBuilder.withUpdatedSinceFilter(
                    ZonedDateTime.ofInstant(watermarkManager.getWatermark(), ZoneOffset.UTC));
        }
        final GitHubSecurityAdvisoryClient client = clientBuilder.build();

        return new GitHubVulnDataSource(watermarkManager, client, config.getAliasSyncEnabled());
    }

    private GitHubTokenProvider createTokenProvider(final GithubVulnDataSourceConfigV1 config) {
        requireNonNull(httpClient, "httpClient must not be null");
        if (config.getApiToken() != null) {
            return new StaticTokenProvider(config.getApiToken());
        }
        return new GitHubAppTokenProvider(
                config.getAppId(),
                config.getInstallationId(),
                config.getAppPrivateKey(),
                GitHubAppTokenProvider.tokenExchangeBaseUrl(config.getApiUrl()),
                httpClient,
                Clock.systemUTC());
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
            final boolean hasPat = config.getApiToken() != null;
            final boolean hasApp = config.getAppId() != null
                    || config.getInstallationId() != null
                    || config.getAppPrivateKey() != null;
            if (hasPat && hasApp) {
                throw new InvalidRuntimeConfigException(
                        "Configure either an API Token or GitHub App credentials, not both");
            }
            if (!hasPat && !hasApp) {
                throw new InvalidRuntimeConfigException(
                        "No authentication configured; provide an API Token or GitHub App credentials");
            }
            if (hasApp && (config.getAppId() == null
                    || config.getInstallationId() == null
                    || config.getAppPrivateKey() == null)) {
                throw new InvalidRuntimeConfigException(
                        "GitHub App authentication requires App ID, Installation ID and App Private Key");
            }
        });
    }

}
