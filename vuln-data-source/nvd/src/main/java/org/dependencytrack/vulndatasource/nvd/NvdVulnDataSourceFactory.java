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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
@NullMarked
final class NvdVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable, Testable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdVulnDataSourceFactory.class);

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable KeyValueStore kvStore;
    private @Nullable ObjectMapper objectMapper;
    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "nvd";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return NvdVulnDataSource.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST + 110;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.kvStore = serviceRegistry.require(KeyValueStore.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.objectMapper = new ObjectMapper()
                .configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true)
                .configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true)
                .registerModule(new JavaTimeModule());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new NvdVulnDataSourceConfigV1()
                .withEnabled(true)
                .withCveFeedsUrl(URI.create("https://nvd.nist.gov/feeds"));

        return RuntimeConfigSpec.of(defaultConfig, config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getCveFeedsUrl() == null) {
                throw new InvalidRuntimeConfigException("No CVE feeds URL provided");
            }
        });
    }

    @Override
    public boolean isDataSourceEnabled() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        return configRegistry.getRuntimeConfig(NvdVulnDataSourceConfigV1.class).isEnabled();
    }

    @Override
    public VulnDataSource create() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(kvStore, "kvStore must not be null");

        final var config = configRegistry.getRuntimeConfig(NvdVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }

        final List<NvdDataFeed> feeds = IntStream
                .range(2002, LocalDate.now().getYear() + 1)
                .boxed()
                .sorted(Comparator.reverseOrder())
                .map(NvdDataFeed.YearDataFeed::new)
                .collect(Collectors.toList());
        feeds.add(resolveIncrementalFeed(config.getCveFeedsUrl().toString()));

        final List<String> feedNames = feeds.stream().map(NvdDataFeed::name).toList();
        final var watermarkManager = new WatermarkManager(kvStore, feedNames);

        return new NvdVulnDataSource(watermarkManager, objectMapper, httpClient, config.getCveFeedsUrl().toString(), feeds);
    }

    private NvdDataFeed resolveIncrementalFeed(final String feedsUrl) {
        requireNonNull(httpClient, "httpClient must not be null");

        final var modifiedMetaUri = URI.create(
                "%s/json/cve/2.0/nvdcve-2.0-modified.meta".formatted(feedsUrl));

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(modifiedMetaUri)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        try {
            final HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200 && !response.body().isBlank()) {
                LOGGER.debug("NVD modified feed is available (HTTP {}), using ModifiedDataFeed", response.statusCode());
                return new NvdDataFeed.ModifiedDataFeed();
            }
            LOGGER.warn(
                    "NVD modified feed probe returned HTTP {} — falling back to RecentDataFeed",
                    response.statusCode());
        } catch (IOException e) {
            LOGGER.warn("NVD modified feed probe failed ({}), falling back to RecentDataFeed", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("NVD modified feed probe interrupted, falling back to RecentDataFeed");
        }

        return new NvdDataFeed.RecentDataFeed();
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        requireNonNull(configRegistry, "configRegistry has not been initialized");
        requireNonNull(httpClient, "httpClient has not been initialized");
        requireNonNull(runtimeConfig, "runtimeConfig must not be null");

        final var nvdConfig = (NvdVulnDataSourceConfigV1) runtimeConfig;

        final var testResult = ExtensionTestResult.ofChecks("connection", "feed_format");

        if (!nvdConfig.isEnabled()) {
            return testResult;
        }

        final URI feedsUrl = !nvdConfig.getCveFeedsUrl().getPath().endsWith("/")
                ? URI.create(nvdConfig.getCveFeedsUrl().toString() + "/")
                : nvdConfig.getCveFeedsUrl();
        final URI metadataUri = feedsUrl.resolve("json/cve/2.0/nvdcve-2.0-modified.meta");

        if (!configRegistry
                .getDeploymentConfig()
                .getOptionalValue("allow-local-connections", boolean.class)
                .orElse(false)) {
            try {
                final var hostAddress = InetAddress.getByName(feedsUrl.getHost());
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

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(metadataUri)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.warn("Failed to connect to {}", metadataUri, e);
            return testResult.fail("connection", "Connection failed, check logs for details");
        }

        if (response.statusCode() != 200) {
            LOGGER.warn("Unexpected response code {} from {}", response.statusCode(), metadataUri);
            return testResult.fail("connection", "Unexpected response code, check logs for details");
        }

        testResult.pass("connection");

        try {
            var _ = NvdDataFeedMetadata.of(response.body());
            testResult.pass("feed_format");
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to parse feed metadata from {}", metadataUri, e);
            testResult.fail("feed_format", "Failed to parse feed metadata, check logs for details");
        }

        return testResult;
    }

}
