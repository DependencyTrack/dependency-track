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
package org.dependencytrack.vulndatasource.jvn;

import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.time.Year;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.1.0
 */
@NullMarked
final class JvnVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable, Testable {

    private static final Logger LOGGER = LoggerFactory.getLogger(JvnVulnDataSourceFactory.class);

    // JVN iPedia has data reaching back to 1998; this bounds the initial backfill.
    private static final int DEFAULT_START_YEAR = 1998;

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable KeyValueStore kvStore;
    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "jvn";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return JvnVulnDataSource.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST + 90;
    }

    @Override
    public void init(final ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.kvStore = serviceRegistry.require(KeyValueStore.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new JvnVulnDataSourceConfigV1()
                .withEnabled(false)
                .withFeedBaseUrl(URI.create(JvnClient.DEFAULT_FEED_BASE_URL))
                .withStartYear(DEFAULT_START_YEAR);

        return RuntimeConfigSpec.of(defaultConfig, config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getFeedBaseUrl() == null) {
                throw new InvalidRuntimeConfigException("No JVN data feed base URL provided");
            }
            if (config.getStartYear() != null && config.getStartYear() < 1998) {
                throw new InvalidRuntimeConfigException("startYear must be 1998 or later");
            }
        });
    }

    @Override
    public boolean isDataSourceEnabled() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        return configRegistry.getRuntimeConfig(JvnVulnDataSourceConfigV1.class).isEnabled();
    }

    @Override
    public VulnDataSource create() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(kvStore, "kvStore must not be null");
        requireNonNull(httpClient, "httpClient must not be null");

        final var config = configRegistry.getRuntimeConfig(JvnVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final int startYear = config.getStartYear() != null ? config.getStartYear() : DEFAULT_START_YEAR;
        final int endYear = Year.now(ZoneOffset.UTC).getValue();

        // Feed-digest keys are the detail-feed filenames, so a run only re-fetches changed years.
        final List<String> feedNames = new ArrayList<>();
        for (int year = startYear; year <= endYear; year++) {
            feedNames.add(JvnClient.detailFeedFilename(year));
        }

        final var watermarkManager = new WatermarkManager(kvStore, feedNames);
        final var client = new JvnClient(httpClient, feedBaseUrlOf(config));
        return new JvnVulnDataSource(client, watermarkManager, startYear, endYear);
    }

    @Override
    public ExtensionTestResult test(final @Nullable RuntimeConfig runtimeConfig) {
        requireNonNull(configRegistry, "configRegistry has not been initialized");
        requireNonNull(httpClient, "httpClient has not been initialized");
        requireNonNull(runtimeConfig, "runtimeConfig must not be null");

        final var jvnConfig = (JvnVulnDataSourceConfigV1) runtimeConfig;
        final var testResult = ExtensionTestResult.ofChecks("connection", "feed_format");
        if (!jvnConfig.isEnabled()) {
            return testResult;
        }

        final String feedBaseUrl = feedBaseUrlOf(jvnConfig);
        final URI baseUri = URI.create(feedBaseUrl);

        if (!configRegistry
                .getDeploymentConfig()
                .getOptionalValue("allow-local-connections", boolean.class)
                .orElse(false)) {
            try {
                final var hostAddress = InetAddress.getByName(baseUri.getHost());
                if (hostAddress.isLoopbackAddress()
                        || hostAddress.isLinkLocalAddress()
                        || hostAddress.isSiteLocalAddress()
                        || hostAddress.isAnyLocalAddress()) {
                    return testResult.fail("connection", "Connection to local hosts is not allowed");
                }
            } catch (UnknownHostException e) {
                return testResult.fail("connection", "Unknown host");
            }
        }

        final int year = Year.now(ZoneOffset.UTC).getValue();
        final URI probeUri = URI.create(feedBaseUrl + "/detail/" + JvnClient.detailFeedFilename(year));
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(probeUri)
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();

        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofByteArray());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.warn("Failed to connect to {}", probeUri, e);
            return testResult.fail("connection", "Connection failed, check logs for details");
        }

        if (response.statusCode() != 200) {
            LOGGER.warn("Unexpected response code {} from {}", response.statusCode(), probeUri);
            return testResult.fail("connection", "Unexpected response code, check logs for details");
        }
        testResult.pass("connection");

        try {
            var _ = JvnDetailParser.parse(response.body());
            testResult.pass("feed_format");
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to parse detail feed from {}", probeUri, e);
            testResult.fail("feed_format", "Failed to parse detail feed, check logs for details");
        }

        return testResult;
    }

    private static String feedBaseUrlOf(final JvnVulnDataSourceConfigV1 config) {
        return config.getFeedBaseUrl() != null
                ? config.getFeedBaseUrl().toString()
                : JvnClient.DEFAULT_FEED_BASE_URL;
    }
}
