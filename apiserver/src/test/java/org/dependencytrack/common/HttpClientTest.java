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
import com.github.tomakehurst.wiremock.http.RequestMethod;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.matching.RequestPatternBuilder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.support.net.OutboundConnectionDeniedException;
import org.dependencytrack.support.net.TransientNetworkErrors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class HttpClientTest {

    private static final String TEST_CLUSTER_ID = "test-cluster-id";

    @Test
    void shouldCreateWithDefaults() {
        final var config = new SmallRyeConfigBuilder().build();

        final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.userAgent()).startsWith("Dependency-Track vUnknown (");
        assertThat(client.userAgent()).endsWith("ManagedHttpClient/" + TEST_CLUSTER_ID);
        assertThat(client.connectTimeout()).hasValue(Duration.ofSeconds(30));
        assertThat(client.followRedirects()).isEqualTo(java.net.http.HttpClient.Redirect.NORMAL);
        assertThat(client.authenticator()).isEmpty();
    }

    @Test
    void shouldCreateWithCustomConfig() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.build-info.application.name", "TestApp")
                .withDefaultValue("alpine.build-info.application.version", "1.2.3")
                .withDefaultValue("dt.http.connect-timeout-ms", "10000")
                .build();

        final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.userAgent())
                .isEqualTo("TestApp v1.2.3 (%s; %s; %s) ManagedHttpClient/%s"
                        .formatted(
                                System.getProperty("os.arch"),
                                System.getProperty("os.name"),
                                System.getProperty("os.version"),
                                TEST_CLUSTER_ID));
        assertThat(client.connectTimeout()).hasValue(Duration.ofSeconds(10));
    }

    @Test
    void shouldCreateWithProxyAuthentication() throws Exception {
        final var config = new SmallRyeConfigBuilder().build();

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("proxy.example.com");
        proxyConfig.setPort(8080);
        proxyConfig.setUsername("user");
        proxyConfig.setPassword("pass");

        final var client = HttpClient.create(config, proxyConfig, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth =
                requestProxyAuth(client.authenticator().get());
        assertThat(auth).isNotNull();
        assertThat(auth.getUserName()).isEqualTo("user");
        assertThat(auth.getPassword()).isEqualTo("pass".toCharArray());
    }

    @Test
    void shouldCreateWithProxyDomainAuthentication() throws Exception {
        final var config = new SmallRyeConfigBuilder().build();

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("proxy.example.com");
        proxyConfig.setPort(8080);
        proxyConfig.setDomain("CORP");
        proxyConfig.setUsername("user");
        proxyConfig.setPassword("pass");

        final var client = HttpClient.create(config, proxyConfig, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth =
                requestProxyAuth(client.authenticator().get());
        assertThat(auth).isNotNull();
        assertThat(auth.getUserName()).isEqualTo("CORP\\user");
    }

    @Test
    void shouldNotProvideAuthForNonProxyRequests() throws Exception {
        final var config = new SmallRyeConfigBuilder().build();

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("proxy.example.com");
        proxyConfig.setPort(8080);
        proxyConfig.setUsername("user");
        proxyConfig.setPassword("pass");

        final var client = HttpClient.create(config, proxyConfig, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth =
                requestServerAuth(client.authenticator().get());
        assertThat(auth).isNull();
    }

    @Test
    void shouldNotConfigureAuthenticatorWithoutCredentials() {
        final var config = new SmallRyeConfigBuilder().build();

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("proxy.example.com");
        proxyConfig.setPort(8080);

        final var client = HttpClient.create(config, proxyConfig, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isEmpty();
    }

    @Test
    void shouldSendBasicProxyAuthorizationOverHttpsConnect() throws Exception {
        // Start a fake HTTP proxy: first CONNECT yields a 407 Basic challenge,
        // second CONNECT captures headers and returns 502. We only care that the
        // JDK retries with Proxy-Authorization, not that the tunnel succeeds.
        //
        // NB: Two accepts are required because the JDK closes the first connection after receiving the 407.
        try (final var proxy = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            final CompletableFuture<List<String>> secondRequest = new CompletableFuture<>();

            final Thread acceptor = Thread.startVirtualThread(() -> {
                try (final Socket firstConnection = proxy.accept()) {
                    readRequestLines(firstConnection);
                    final String response = """
                            HTTP/1.1 407 Proxy Authentication Required
                            Proxy-Authenticate: Basic realm="proxy"
                            Content-Length: 0
                            Connection: close

                            """.replace("\n", "\r\n");
                    firstConnection.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
                    firstConnection.getOutputStream().flush();
                } catch (IOException e) {
                    secondRequest.completeExceptionally(e);
                    return;
                }

                try (final Socket secondConnection = proxy.accept()) {
                    secondRequest.complete(readRequestLines(secondConnection));
                    final String response = """
                            HTTP/1.1 502 Bad Gateway
                            Content-Length: 0
                            Connection: close

                            """.replace("\n", "\r\n");
                    secondConnection.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
                    secondConnection.getOutputStream().flush();
                } catch (IOException e) {
                    secondRequest.completeExceptionally(e);
                }
            });

            final var proxyConfig = new ProxyConfig();
            proxyConfig.setHost(proxy.getInetAddress().getHostAddress());
            proxyConfig.setPort(proxy.getLocalPort());
            proxyConfig.setUsername("user");
            proxyConfig.setPassword("pass");

            try (final HttpClient client = HttpClient.create(
                    new SmallRyeConfigBuilder().build(),
                    proxyConfig,
                    new SimpleMeterRegistry(),
                    () -> TEST_CLUSTER_ID)) {
                try {
                    client.send(
                            HttpRequest.newBuilder(URI.create("https://target.example.com/"))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding());
                } catch (IOException _) {
                    // Expected since tunnel is never established due to 502 response.
                }
            }

            final List<String> secondRequestLines = secondRequest.get(10, TimeUnit.SECONDS);
            acceptor.join(TimeUnit.SECONDS.toMillis(50));

            assertThat(secondRequestLines).isNotEmpty();
            assertThat(secondRequestLines.getFirst()).startsWith("CONNECT target.example.com:443 ");
            final String expectedCredentials =
                    Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
            assertThat(secondRequestLines)
                    .anyMatch(line -> line.equalsIgnoreCase("Proxy-Authorization: Basic " + expectedCredentials));
        }
    }

    @Test
    void createShouldRejectInvalidAllowedDestinations() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "external,10.0.0.0/abc")
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID))
                .withMessage("Invalid prefix length in 10.0.0.0/abc");
    }

    @Test
    void sendShouldRejectDestinationDeniedByPolicy(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(anyUrl()).willReturn(aResponse().withStatus(200)));

        try (final var client = HttpClient.create(
                new SmallRyeConfigBuilder().build(), null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            assertThatExceptionOfType(OutboundConnectionDeniedException.class)
                    .isThrownBy(() -> client.send(
                            HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding()))
                    .withMessage(
                            "Connections to localhost (127.0.0.1) are not allowed by dt.outbound.allowed-destinations")
                    .satisfies(exception -> assertThat(TransientNetworkErrors.isTransient(exception))
                            .isFalse());
        }

        verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void sendShouldCheckOnlyLiteralAddressesWhenProxied() throws Exception {
        final int closedPort;
        try (final var serverSocket = new ServerSocket(0)) {
            closedPort = serverSocket.getLocalPort();
        }

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("127.0.0.1");
        proxyConfig.setPort(closedPort);

        try (final var client = HttpClient.create(
                new SmallRyeConfigBuilder().build(), proxyConfig, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            assertThatExceptionOfType(OutboundConnectionDeniedException.class)
                    .isThrownBy(() -> client.send(
                            HttpRequest.newBuilder(URI.create("http://169.254.169.254/"))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding()));

            // The proxy resolves hostnames, so the request reaches the (closed) proxy port
            // instead of failing on a local lookup.
            assertThatExceptionOfType(ConnectException.class)
                    .isThrownBy(() -> client.send(
                            HttpRequest.newBuilder(URI.create("http://target.invalid/"))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding()));
        }
    }

    @Test
    void sendShouldFollowRedirect(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse().withStatus(302).withHeader("Location", "/bar")));
        stubFor(get(urlPathEqualTo("/bar"))
                .willReturn(aResponse().withStatus(200).withBody("bar")));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo("bar");
        }
    }

    @Test
    void sendAsyncWithPushPromiseHandlerShouldFollowRedirect(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse().withStatus(302).withHeader("Location", "/bar")));
        stubFor(get(urlPathEqualTo("/bar"))
                .willReturn(aResponse().withStatus(200).withBody("bar")));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<String> response = client.sendAsync(
                            HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString(),
                            (_, _, _) -> {})
                    .get(5, TimeUnit.SECONDS);

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo("bar");
        }
    }

    @Test
    void sendShouldRejectRedirectToDestinationDeniedByPolicy(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://127.0.0.1:%d/bar".formatted(wmRuntimeInfo.getHttpPort()))));
        stubFor(get(urlPathEqualTo("/bar")).willReturn(aResponse().withStatus(200)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "localhost")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            assertThatExceptionOfType(OutboundConnectionDeniedException.class)
                    .isThrownBy(() -> client.send(
                            HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding()))
                    .withMessage(
                            "Connections to 127.0.0.1 (127.0.0.1) are not allowed by dt.outbound.allowed-destinations");
        }

        verify(0, getRequestedFor(urlPathEqualTo("/bar")));
    }

    @Test
    void sendAsyncShouldRejectRedirectToDestinationDeniedByPolicy(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://127.0.0.1:%d/bar".formatted(wmRuntimeInfo.getHttpPort()))));
        stubFor(get(urlPathEqualTo("/bar")).willReturn(aResponse().withStatus(200)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "localhost")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final CompletableFuture<HttpResponse<Void>> future = client.sendAsync(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    HttpResponse.BodyHandlers.discarding());

            assertThat(future)
                    .failsWithin(Duration.ofSeconds(5))
                    .withThrowableOfType(ExecutionException.class)
                    .withCauseInstanceOf(OutboundConnectionDeniedException.class);
        }

        verify(0, getRequestedFor(urlPathEqualTo("/bar")));
    }

    @Test
    void sendShouldReturnRedirectResponseWhenMaxRedirectsExceeded(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "/foo")
                        .withBody("redirect")));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(302);
            assertThat(response.body()).isEqualTo("redirect");
        }

        verify(6, getRequestedFor(urlPathEqualTo("/foo")));
    }

    @Test
    void sendShouldNotFollowRedirectToUriWithoutHost(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse().withStatus(302).withHeader("Location", "http://invalid_host/bar")));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<Void> response = client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    HttpResponse.BodyHandlers.discarding());

            assertThat(response.statusCode()).isEqualTo(302);
        }
    }

    @Test
    void sendShouldNotPassRedirectResponseToBodyHandler(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "/bar")
                        .withBody("redirect")));
        stubFor(get(urlPathEqualTo("/bar"))
                .willReturn(aResponse().withStatus(200).withBody("bar")));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        final var handledStatusCodes = new ArrayList<Integer>();
        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    responseInfo -> {
                        handledStatusCodes.add(responseInfo.statusCode());
                        return HttpResponse.BodySubscribers.ofString(StandardCharsets.UTF_8);
                    });

            assertThat(response.body()).isEqualTo("bar");
        }

        assertThat(handledStatusCodes).containsExactly(200);
    }

    @ParameterizedTest(name = "[{index}] status={0} method={1} expectedMethod={2}")
    @CsvSource(textBlock = """
        301, POST, GET
        302, POST, GET
        302, PUT,  PUT
        303, PUT,  GET
        303, HEAD, HEAD
        307, POST, POST
        308, PUT,  PUT
        """)
    void sendShouldApplyRedirectMethodRules(
            int statusCode, String method, String expectedMethod, WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(any(urlPathEqualTo("/foo"))
                .willReturn(aResponse().withStatus(statusCode).withHeader("Location", "/bar")));
        stubFor(any(urlPathEqualTo("/bar")).willReturn(aResponse().withStatus(200)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        final boolean hasBody = !"HEAD".equals(method);
        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final HttpResponse<Void> response = client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .header("Content-Type", "application/json")
                            .method(
                                    method,
                                    hasBody
                                            ? HttpRequest.BodyPublishers.ofString("{}")
                                            : HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.discarding());

            assertThat(response.statusCode()).isEqualTo(200);
        }

        final var expectedRequest = RequestPatternBuilder.newRequestPattern(
                RequestMethod.fromString(expectedMethod), urlPathEqualTo("/bar"));
        if (expectedMethod.equals(method) && hasBody) {
            expectedRequest
                    .withHeader("Content-Type", equalTo("application/json"))
                    .withRequestBody(equalTo("{}"));
        } else if (hasBody) {
            expectedRequest.withoutHeader("Content-Type");
        }
        verify(expectedRequest);
    }

    @Test
    void sendShouldStripCredentialsOnCrossOriginRedirect(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://127.0.0.1:%d/bar".formatted(wmRuntimeInfo.getHttpPort()))));
        stubFor(get(urlPathEqualTo("/bar")).willReturn(aResponse().withStatus(200)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .header("Authorization", "Bearer secret")
                            .header("Cookie", "session=secret")
                            .header("X-Custom", "foo")
                            .build(),
                    HttpResponse.BodyHandlers.discarding());
        }

        verify(getRequestedFor(urlPathEqualTo("/bar"))
                .withoutHeader("Authorization")
                .withoutHeader("Cookie")
                .withHeader("X-Custom", equalTo("foo")));
    }

    @Test
    void sendShouldKeepCredentialsOnSameOriginRedirect(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/foo"))
                .willReturn(aResponse().withStatus(302).withHeader("Location", "/bar")));
        stubFor(get(urlPathEqualTo("/bar")).willReturn(aResponse().withStatus(200)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            client.send(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .header("Authorization", "Bearer secret")
                            .build(),
                    HttpResponse.BodyHandlers.discarding());
        }

        verify(getRequestedFor(urlPathEqualTo("/bar")).withHeader("Authorization", equalTo("Bearer secret")));
    }

    @ParameterizedTest(name = "[{index}] {0} {1} {2} -> {3}")
    @CsvSource(textBlock = """
        https://a.example/x, 302, http://b.example/,
        https://a.example/x, 302, https://b.example/, https://b.example/
        http://a.example/x,  302, https://b.example/, https://b.example/
        http://a.example/x,  301, /y,                 http://a.example/y
        http://a.example/x,  307, //b.example/y,      http://b.example/y
        http://a.example/x,  302, ftp://b.example/,
        http://a.example/x,  302, http://in_valid/,
        http://a.example/x,  200, /y,
        http://a.example/x,  304, /y,
        """)
    void redirectUriShouldResolveFollowableLocations(
            URI requestUri, int statusCode, String location, URI expectedRedirectUri) throws Exception {
        final var headers =
                HttpHeaders.of(location == null ? Map.of() : Map.of("Location", List.of(location)), (_, _) -> true);

        assertThat(HttpClient.redirectUri(requestUri, statusCode, headers)).isEqualTo(expectedRedirectUri);
    }

    @ParameterizedTest(name = "[{index}] {0} {1}")
    @CsvSource(textBlock = """
        302, http://a b/
        """)
    void redirectUriShouldRejectMissingOrInvalidLocation(int statusCode, String location) {
        final var headers =
                HttpHeaders.of(location == null ? Map.of() : Map.of("Location", List.of(location)), (_, _) -> true);

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> HttpClient.redirectUri(URI.create("http://a.example/x"), statusCode, headers));
    }

    @Test
    void sendShouldFailOnRedirectWithoutLocation(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/foo")).willReturn(aResponse().withStatus(302)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> client.send(
                            HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString()));
        }
    }

    @Test
    void sendAsyncShouldFailOnRedirectWithoutLocation(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/foo")).willReturn(aResponse().withStatus(302)));

        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                .build();

        try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
            final CompletableFuture<HttpResponse<String>> future = client.sendAsync(
                    HttpRequest.newBuilder(URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/foo"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(future)
                    .failsWithin(Duration.ofSeconds(5))
                    .withThrowableOfType(ExecutionException.class)
                    .withCauseInstanceOf(IOException.class);
        }
    }

    @Test
    void sendAsyncShouldCloseRedirectedConnectionWhenCancelled() throws Exception {
        try (final var server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            final var redirectedRequestReceived = new CompletableFuture<Void>();
            final var connectionClosed = new CompletableFuture<Void>();

            Thread.startVirtualThread(() -> {
                try (final Socket connection = server.accept()) {
                    readRequestLines(connection);
                    final String response = """
                        HTTP/1.1 302 Found
                        Location: /bar
                        Content-Length: 0
                        Connection: close

                        """.replace("\n", "\r\n");
                    connection.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
                    connection.getOutputStream().flush();
                } catch (IOException e) {
                    redirectedRequestReceived.completeExceptionally(e);
                    return;
                }

                try (final Socket connection = server.accept()) {
                    readRequestLines(connection);
                    redirectedRequestReceived.complete(null);
                    if (connection.getInputStream().read() == -1) {
                        connectionClosed.complete(null);
                    }
                } catch (IOException e) {
                    connectionClosed.complete(null);
                }
            });

            final var config = new SmallRyeConfigBuilder()
                    .withDefaultValue("dt.outbound.allowed-destinations", "loopback")
                    .build();

            try (final var client = HttpClient.create(config, null, new SimpleMeterRegistry(), () -> TEST_CLUSTER_ID)) {
                final CompletableFuture<HttpResponse<Void>> future = client.sendAsync(
                        HttpRequest.newBuilder(URI.create("http://127.0.0.1:%d/foo".formatted(server.getLocalPort())))
                                .build(),
                        HttpResponse.BodyHandlers.discarding());

                redirectedRequestReceived.get(5, TimeUnit.SECONDS);
                future.cancel(true);

                assertThat(connectionClosed).succeedsWithin(Duration.ofSeconds(5));
            }
        }
    }

    private static PasswordAuthentication requestProxyAuth(Authenticator authenticator) throws Exception {
        return Authenticator.requestPasswordAuthentication(
                authenticator,
                "proxy.example.com",
                InetAddress.getLoopbackAddress(),
                8080,
                "http",
                "realm",
                "basic",
                URI.create("http://target.example.com").toURL(),
                Authenticator.RequestorType.PROXY);
    }

    private static PasswordAuthentication requestServerAuth(Authenticator authenticator) throws Exception {
        return Authenticator.requestPasswordAuthentication(
                authenticator,
                "server.example.com",
                InetAddress.getLoopbackAddress(),
                443,
                "https",
                "realm",
                "basic",
                URI.create("https://server.example.com").toURL(),
                Authenticator.RequestorType.SERVER);
    }

    private static List<String> readRequestLines(final Socket socket) throws IOException {
        final var reader =
                new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));

        final var lines = new ArrayList<String>();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            lines.add(line);
        }

        return lines;
    }
}
