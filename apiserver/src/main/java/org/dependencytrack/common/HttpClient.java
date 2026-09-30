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
import org.dependencytrack.support.net.OutboundConnectionDeniedException;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.function.Supplier;

/**
 * @since 5.0.0
 */
public final class HttpClient extends java.net.http.HttpClient {

    private static final int MAX_REDIRECTS = 5;
    private static final Set<Integer> REDIRECT_STATUS_CODES = Set.of(301, 302, 303, 307, 308);
    private static final Set<String> CROSS_ORIGIN_SENSITIVE_HEADERS =
            Set.of("authorization", "cookie", "origin", "proxy-authorization", "referer");
    private static final Set<String> REQUEST_BODY_HEADERS =
            Set.of("content-encoding", "content-language", "content-location", "content-type");

    public static final HttpClient INSTANCE = create(
            ConfigProvider.getConfig(), ProxyUtil.getProxyConfig(), Metrics.globalRegistry, ClusterInfo::getClusterId);

    private final java.net.http.HttpClient delegate;
    private final java.net.ProxySelector proxySelector;
    private final OutboundConnectionPolicy outboundConnectionPolicy;
    private final String userAgentPrefix;
    private final Supplier<String> clusterIdSupplier;
    private volatile String userAgent;

    private HttpClient(
            java.net.http.HttpClient delegate,
            java.net.ProxySelector proxySelector,
            OutboundConnectionPolicy outboundConnectionPolicy,
            String userAgentPrefix,
            Supplier<String> clusterIdSupplier) {
        this.delegate = delegate;
        this.proxySelector = proxySelector;
        this.outboundConnectionPolicy = outboundConnectionPolicy;
        this.userAgentPrefix = userAgentPrefix;
        this.clusterIdSupplier = clusterIdSupplier;
    }

    static HttpClient create(
            Config config, ProxyConfig proxyConfig, MeterRegistry meterRegistry, Supplier<String> clusterIdSupplier) {
        final String appName = config.getOptionalValue("alpine.build-info.application.name", String.class)
                .orElse("Dependency-Track");
        final String appVersion = config.getOptionalValue("alpine.build-info.application.version", String.class)
                .orElse("Unknown");
        final String userAgentPrefix = "%s v%s (%s; %s; %s) ManagedHttpClient/"
                .formatted(
                        appName,
                        appVersion,
                        SystemUtil.getOsArchitecture(),
                        SystemUtil.getOsName(),
                        SystemUtil.getOsVersion());

        final long connectTimeoutMs = config.getOptionalValue(AlpineConfigKeys.HTTP_CONNECT_TIMEOUT_MS, long.class)
                .orElse(30_000L);

        final var outboundConnectionPolicy = OutboundConnectionPolicy.of(
                config.getOptionalValues(ConfigKeys.OUTBOUND_ALLOWED_DESTINATIONS, String.class)
                        .orElse(List.of("external", "private")));

        final var proxySelector = new ProxySelector(proxyConfig);
        final var clientBuilder = java.net.http.HttpClient.newBuilder()
                .proxy(proxySelector)
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(Redirect.NEVER);

        if (proxyConfig != null && proxyConfig.getUsername() != null && proxyConfig.getPassword() != null) {
            // Basic auth is disabled by default for the JDK's HttpClient, with the following justification:
            //
            // > "Basic" results in effectively the cleartext transmission of
            // > the user's password over the physical network.
            // https://raw.githubusercontent.com/openjdk/jdk/master/src/java.base/share/conf/net.properties
            //
            // However, basic auth is how most proxies handle authentication.
            // Having it disabled effectively prevents many users with corporate proxies from using DT.
            //
            // Note: setting the property here is just a fallback. The JDK evaluates the system property
            // *once*, the first time it is read. If any other code path initializes a HttpClient before
            // we do, it might cache the default "Basic" value. The only bullet-proof fix is to set this
            // as JVM argument, i.e. in Dockerfile's `CMD` or via `JAVA_OPTIONS` env var.
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");

            final String username = proxyConfig.getDomain() != null
                    ? proxyConfig.getDomain() + "\\" + proxyConfig.getUsername()
                    : proxyConfig.getUsername();

            clientBuilder.authenticator(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    if (getRequestorType() == RequestorType.PROXY) {
                        return new PasswordAuthentication(
                                username, proxyConfig.getPassword().toCharArray());
                    }

                    return null;
                }
            });
        }

        return new HttpClient(
                MicrometerHttpClient.instrumentationBuilder(clientBuilder.build(), meterRegistry)
                        .build(),
                proxySelector,
                outboundConnectionPolicy,
                userAgentPrefix,
                clusterIdSupplier);
    }

    public OutboundConnectionPolicy outboundConnectionPolicy() {
        return outboundConnectionPolicy;
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
        // Report NORMAL despite delegate being configured with NEVER.
        // We handle redirects manually to be able to apply the outbound
        // connection policy.
        return Redirect.NORMAL;
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
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        HttpRequest currentRequest = request;
        for (int redirects = 0; ; redirects++) {
            requireAllowedDestination(currentRequest.uri());

            final boolean mayRedirect = redirects < MAX_REDIRECTS;
            final HttpResponse<T> response = delegate.send(
                    withUserAgent(currentRequest),
                    discardingRedirectBody(currentRequest, responseBodyHandler, mayRedirect));

            final HttpRequest redirectRequest = mayRedirect ? redirectRequest(currentRequest, response) : null;
            if (redirectRequest == null) {
                return response;
            }

            currentRequest = redirectRequest;
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        final var result = new RedirectingFuture<HttpResponse<T>>();
        sendAsync(request, responseBodyHandler, null, 0, result);
        return result;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        final var result = new RedirectingFuture<HttpResponse<T>>();
        sendAsync(request, responseBodyHandler, pushPromiseHandler, 0, result);
        return result;
    }

    private <T> void sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.@Nullable PushPromiseHandler<T> pushPromiseHandler,
            int redirects,
            RedirectingFuture<HttpResponse<T>> result) {
        try {
            requireAllowedDestination(request.uri());
        } catch (IOException e) {
            result.completeExceptionally(e);
            return;
        }

        final boolean mayRedirect = redirects < MAX_REDIRECTS;
        final HttpResponse.BodyHandler<T> hopBodyHandler =
                discardingRedirectBody(request, responseBodyHandler, mayRedirect);
        final CompletableFuture<HttpResponse<T>> hop = pushPromiseHandler == null
                ? delegate.sendAsync(withUserAgent(request), hopBodyHandler)
                : delegate.sendAsync(withUserAgent(request), hopBodyHandler, pushPromiseHandler);
        result.start(hop);
        var _ = hop.whenComplete((response, throwable) -> {
            if (throwable != null) {
                result.completeExceptionally(throwable);
                return;
            }

            try {
                final HttpRequest redirectRequest = mayRedirect ? redirectRequest(request, response) : null;
                if (redirectRequest == null) {
                    result.complete(response);
                } else {
                    sendAsync(redirectRequest, responseBodyHandler, pushPromiseHandler, redirects + 1, result);
                }
            } catch (IOException | RuntimeException e) {
                result.completeExceptionally(e);
            }
        });
    }

    private void requireAllowedDestination(URI uri) throws IOException {
        final String host = uri.getHost();

        // When proxied, the proxy resolves the host.
        // Only a literal address can be checked here.
        if (isProxied(uri) && !isIpLiteral(host)) {
            return;
        }

        try {
            outboundConnectionPolicy.requireAllowed(host);
        } catch (OutboundConnectionDeniedException e) {
            throw new OutboundConnectionDeniedException(
                    "%s by %s".formatted(e.getMessage(), ConfigKeys.OUTBOUND_ALLOWED_DESTINATIONS));
        }
    }

    private static boolean isIpLiteral(String host) {
        try {
            var _ = InetAddress.ofLiteral(host);
            return true;
        } catch (IllegalArgumentException _) {
            return false;
        }
    }

    private static <T> HttpResponse.BodyHandler<T> discardingRedirectBody(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler, boolean mayRedirect) {
        return responseInfo -> {
            if (!mayRedirect) {
                return responseBodyHandler.apply(responseInfo);
            }

            try {
                return redirectUri(request.uri(), responseInfo.statusCode(), responseInfo.headers()) != null
                        ? HttpResponse.BodySubscribers.replacing(null)
                        : responseBodyHandler.apply(responseInfo);
            } catch (IOException _) {
                return HttpResponse.BodySubscribers.replacing(null);
            }
        };
    }

    private static @Nullable HttpRequest redirectRequest(HttpRequest request, HttpResponse<?> response)
            throws IOException {
        final URI redirectUri = redirectUri(request.uri(), response.statusCode(), response.headers());
        if (redirectUri == null) {
            return null;
        }

        final int statusCode = response.statusCode();
        final boolean changeToGet = (statusCode == 303 && !"HEAD".equals(request.method()))
                || ((statusCode == 301 || statusCode == 302) && "POST".equals(request.method()));
        final boolean crossOrigin = !isSameOrigin(request.uri(), redirectUri);

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(request, (name, _) -> {
                    final String lowerCaseName = name.toLowerCase(Locale.ROOT);
                    return !(crossOrigin && CROSS_ORIGIN_SENSITIVE_HEADERS.contains(lowerCaseName))
                            && !(changeToGet && REQUEST_BODY_HEADERS.contains(lowerCaseName));
                })
                .uri(redirectUri);
        if (changeToGet) {
            requestBuilder.GET();
        }

        return requestBuilder.build();
    }

    static @Nullable URI redirectUri(URI requestUri, int statusCode, HttpHeaders headers) throws IOException {
        if (!REDIRECT_STATUS_CODES.contains(statusCode)) {
            return null;
        }

        final String location = headers.firstValue("Location")
                .orElseThrow(() -> new IOException("HTTP %d response has no Location header".formatted(statusCode)));

        final URI redirectUri;
        try {
            redirectUri = requestUri.resolve(location);
        } catch (IllegalArgumentException e) {
            throw new IOException("HTTP %d response has an invalid Location header".formatted(statusCode), e);
        }

        final String scheme = redirectUri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            return null;
        }
        if (redirectUri.getHost() == null) {
            return null;
        }
        if ("https".equalsIgnoreCase(requestUri.getScheme()) && "http".equalsIgnoreCase(scheme)) {
            return null;
        }

        return redirectUri;
    }

    private static boolean isSameOrigin(URI a, URI b) {
        return a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getHost() != null
                && a.getHost().equalsIgnoreCase(b.getHost())
                && effectivePortOf(a) == effectivePortOf(b);
    }

    private static int effectivePortOf(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }

        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private boolean isProxied(URI uri) {
        return proxySelector.select(uri).stream().anyMatch(proxy -> proxy.type() != Proxy.Type.DIRECT);
    }

    private HttpRequest withUserAgent(HttpRequest request) {
        return HttpRequest.newBuilder(request, (name, _) -> !"User-Agent".equalsIgnoreCase(name))
                .header("User-Agent", userAgent())
                .build();
    }

    /// A [CompletableFuture] wrapping the [Future] of a redirect hop.
    /// Cancellation aborts whatever hop is in flight, replicating the JDK's behavior.
    private static final class RedirectingFuture<T> extends CompletableFuture<T> {

        private volatile boolean cancelled;
        private volatile @Nullable Future<?> hopFuture;

        private void start(Future<?> hopFuture) {
            this.hopFuture = hopFuture;
            if (cancelled) {
                hopFuture.cancel(true);
            }
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            if (mayInterruptIfRunning && !isDone()) {
                cancelled = true;
                final Future<?> hop = this.hopFuture;
                if (hop != null) {
                    hop.cancel(true);
                }
            }

            return super.cancel(mayInterruptIfRunning);
        }
    }
}
