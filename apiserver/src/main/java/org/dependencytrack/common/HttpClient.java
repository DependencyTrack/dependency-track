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
package org.dependencytrack.common;

import alpine.common.util.ProxyConfig;
import alpine.common.util.ProxyUtil;
import alpine.common.util.SystemUtil;
import alpine.config.AlpineConfigKeys;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.java11.instrument.binder.jdk.MicrometerHttpClient;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.PasswordAuthentication;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * @since 5.0.0
 */
public final class HttpClient extends java.net.http.HttpClient {

    public static final HttpClient INSTANCE = create(
            ConfigProvider.getConfig(),
            ProxyUtil.getProxyConfig(),
            Metrics.globalRegistry,
            ClusterInfo::getClusterId);

    private final java.net.http.HttpClient delegate;
    private final String userAgentPrefix;
    private final Supplier<String> clusterIdSupplier;
    private volatile String userAgent;

    private HttpClient(
            java.net.http.HttpClient delegate,
            String userAgentPrefix,
            Supplier<String> clusterIdSupplier) {
        this.delegate = delegate;
        this.userAgentPrefix = userAgentPrefix;
        this.clusterIdSupplier = clusterIdSupplier;
    }

    static HttpClient create(
            Config config,
            ProxyConfig proxyConfig,
            MeterRegistry meterRegistry,
            Supplier<String> clusterIdSupplier) {
        final String appName = config
                .getOptionalValue("alpine.build-info.application.name", String.class)
                .orElse("Dependency-Track");
        final String appVersion = config
                .getOptionalValue("alpine.build-info.application.version", String.class)
                .orElse("Unknown");
        final String userAgentPrefix =
                "%s v%s (%s; %s; %s) ManagedHttpClient/".formatted(
                        appName,
                        appVersion,
                        SystemUtil.getOsArchitecture(),
                        SystemUtil.getOsName(),
                        SystemUtil.getOsVersion());

        final long connectTimeoutMs = config
                .getOptionalValue(AlpineConfigKeys.HTTP_CONNECT_TIMEOUT_MS, long.class)
                .orElse(30_000L);
        final var clientBuilder = java.net.http.HttpClient.newBuilder()
                .proxy(new ProxySelector(proxyConfig))
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(java.net.http.HttpClient.Redirect.NORMAL);

        if (proxyConfig != null && proxyConfig.getUsername() != null && proxyConfig.getPassword() != null) {
            final String username = proxyConfig.getDomain() != null
                    ? proxyConfig.getDomain() + "\\" + proxyConfig.getUsername()
                    : proxyConfig.getUsername();
            clientBuilder.authenticator(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    if (getRequestorType() == RequestorType.PROXY) {
                        return new PasswordAuthentication(username, proxyConfig.getPassword().toCharArray());
                    }

                    return null;
                }
            });
        }

        return new HttpClient(
                MicrometerHttpClient
                        .instrumentationBuilder(clientBuilder.build(), meterRegistry)
                        .build(),
                userAgentPrefix,
                clusterIdSupplier);
    }

    public String userAgent() {
        String userAgent = this.userAgent;
        if (userAgent == null) {
            this.userAgent = userAgent = userAgentPrefix + clusterIdSupplier.get();
        }

        return userAgent;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<java.net.ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        return delegate.send(withUserAgent(request), responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) {
        return delegate.sendAsync(withUserAgent(request), responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return delegate.sendAsync(withUserAgent(request), responseBodyHandler, pushPromiseHandler);
    }

    private HttpRequest withUserAgent(HttpRequest request) {
        return HttpRequest
                .newBuilder(request, (name, value) -> !"User-Agent".equalsIgnoreCase(name))
                .header("User-Agent", userAgent())
                .build();
    }

}
