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

import java.net.Authenticator;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.time.Duration;

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

}
