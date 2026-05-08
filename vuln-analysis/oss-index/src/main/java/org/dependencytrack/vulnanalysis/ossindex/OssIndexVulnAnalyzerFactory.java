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
package org.dependencytrack.vulnanalysis.ossindex;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class OssIndexVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable, Testable {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexVulnAnalyzerFactory.class);

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CacheManager cacheManager;
    private @Nullable HttpClient httpClient;
    private @Nullable ObjectMapper objectMapper;
    private boolean localConnectionsAllowed;

    @Override
    public String extensionName() {
        return "oss-index";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return OssIndexVulnAnalyzer.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        configRegistry = serviceRegistry.require(ConfigRegistry.class);
        cacheManager = serviceRegistry.require(CacheManager.class);
        httpClient = serviceRegistry.require(HttpClient.class);
        objectMapper = new ObjectMapper()
                .disable(FAIL_ON_UNKNOWN_PROPERTIES);
        localConnectionsAllowed = configRegistry
                .getDeploymentConfig()
                .getOptionalValue("allow-local-connections", boolean.class)
                .orElse(false);
    }

    @Override
    public VulnAnalyzer create() {
        requireNonNull(configRegistry);
        requireNonNull(cacheManager);
        requireNonNull(httpClient);
        requireNonNull(objectMapper);

        final var config = configRegistry.getRuntimeConfig(OssIndexVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled");
        }

        if (!localConnectionsAllowed) {
            final String host = config.getApiUrl().getHost();
            if (host != null && isLocalHost(host)) {
                throw new IllegalStateException("""
                        API URL '%s' resolves to a local address, \
                        but local connections are not allowed""".formatted(config.getApiUrl()));
            }
        }

        return new OssIndexVulnAnalyzer(
                cacheManager.getCache("results"),
                httpClient,
                objectMapper,
                config.getApiUrl(),
                config.getUsername(),
                config.getApiToken(),
                config.isAliasSyncEnabled());
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(OssIndexVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new OssIndexVulnAnalyzerConfigV1()
                        .withEnabled(false)
                        .withApiUrl(URI.create("https://ossindex.sonatype.org")),
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
                    if (!config.getApiToken().startsWith("sonatype_pat_") && config.getUsername() == null) {
                        throw new InvalidRuntimeConfigException("No username provided");
                    }
                });
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        requireNonNull(runtimeConfig, "runtimeConfig must not be null");
        requireNonNull(httpClient, "httpClient must not be null");

        final var config = (OssIndexVulnAnalyzerConfigV1) runtimeConfig;
        final var testResult = ExtensionTestResult.ofChecks("connection", "authentication");

        if (!config.isEnabled()) {
            return testResult;
        }

        if (config.getApiUrl() == null) {
            return testResult.fail("connection", "No API URL provided");
        }
        if (config.getApiToken() == null) {
            return testResult.fail("authentication", "No credentials provided");
        }

        final String host = config.getApiUrl().getHost();
        if (!localConnectionsAllowed && host != null && isLocalHost(host)) {
            return testResult.fail("connection", """
                    API URL '%s' resolves to a local address, \
                    but local connections are not allowed""".formatted(config.getApiUrl()));
        }

        final String authHeader;
        if (config.getUsername() != null && config.getApiToken() != null) {
            final String basicAuthCredentials = Base64.getEncoder().encodeToString(
                    "%s:%s".formatted(config.getUsername(), config.getApiToken())
                            .getBytes(StandardCharsets.UTF_8));
            authHeader = "Basic " + basicAuthCredentials;
        } else {
            authHeader = "Bearer " + config.getApiToken();
        }


        final var request = HttpRequest.newBuilder()
                .uri(config.getApiUrl().resolve("/api/v3/component-report"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", authHeader)
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"coordinates\":[\"pkg:maven/org.dependencytrack/noop@0.0.0\"]}"))
                .build();

        final int statusCode;
        try {
            final HttpResponse<Void> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.discarding());
            statusCode = response.statusCode();
        } catch (IOException e) {
            LOGGER.error("Failed to connect to OSS Index at {}", request.uri(), e);
            return testResult.fail("connection", "Connection failed, check logs for details");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return testResult.fail("connection", "Request was interrupted");
        }

        testResult.pass("connection");

        if (Set.of(200, 402, 429).contains(statusCode)) {
            testResult.pass("authentication");
        } else if (statusCode == 401 || statusCode == 403) {
            testResult.fail("authentication", "Authentication failed with status %d".formatted(statusCode));
        } else {
            testResult.fail("connection", "Unexpected response status %d".formatted(statusCode));
        }

        return testResult;
    }

    private boolean isLocalHost(String hostname) {
        try {
            final InetAddress hostAddress = InetAddress.getByName(hostname);
            return hostAddress.isLoopbackAddress()
                    || hostAddress.isLinkLocalAddress()
                    || hostAddress.isSiteLocalAddress()
                    || hostAddress.isAnyLocalAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

}
