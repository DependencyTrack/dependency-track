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
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class HttpClientTest {

    private static final String TEST_CLUSTER_ID = "test-cluster-id";

    @Test
    void shouldCreateWithDefaults() {
        final var config = new SmallRyeConfigBuilder().build();

        final var client = HttpClient.create(
                config,
                null,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

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

        final var client = HttpClient.create(
                config,
                null,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

        assertThat(client.userAgent()).isEqualTo(
                "TestApp v1.2.3 (%s; %s; %s) ManagedHttpClient/%s".formatted(
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

        final var client = HttpClient.create(
                config,
                proxyConfig,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth = requestProxyAuth(client.authenticator().get());
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

        final var client = HttpClient.create(
                config,
                proxyConfig,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth = requestProxyAuth(client.authenticator().get());
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

        final var client = HttpClient.create(
                config,
                proxyConfig,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

        assertThat(client.authenticator()).isPresent();
        final PasswordAuthentication auth = requestServerAuth(client.authenticator().get());
        assertThat(auth).isNull();
    }

    @Test
    void shouldNotConfigureAuthenticatorWithoutCredentials() {
        final var config = new SmallRyeConfigBuilder().build();

        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("proxy.example.com");
        proxyConfig.setPort(8080);

        final var client = HttpClient.create(
                config,
                proxyConfig,
                new SimpleMeterRegistry(),
                () -> TEST_CLUSTER_ID);

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
                    firstConnection.getOutputStream().write(
                            response.getBytes(StandardCharsets.US_ASCII));
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
                    secondConnection.getOutputStream().write(
                            response.getBytes(StandardCharsets.US_ASCII));
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
                            HttpRequest.newBuilder(URI.create("https://target.example.com/")).build(),
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
                    Base64.getEncoder().encodeToString(
                            "user:pass".getBytes(StandardCharsets.UTF_8));
            assertThat(secondRequestLines).anyMatch(
                    line -> line.equalsIgnoreCase(
                            "Proxy-Authorization: Basic " + expectedCredentials));
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
                Authenticator.RequestorType.PROXY
        );
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
                Authenticator.RequestorType.SERVER
        );
    }

    private static List<String> readRequestLines(final Socket socket) throws IOException {
        final var reader = new BufferedReader(
                new InputStreamReader(
                        socket.getInputStream(),
                        StandardCharsets.US_ASCII));

        final var lines = new ArrayList<String>();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            lines.add(line);
        }

        return lines;
    }

}
