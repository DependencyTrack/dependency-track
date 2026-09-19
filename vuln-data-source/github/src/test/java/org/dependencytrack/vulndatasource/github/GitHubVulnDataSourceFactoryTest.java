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

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigValidator;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class GitHubVulnDataSourceFactoryTest
        extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull GitHubVulnDataSourceFactory> {

    protected GitHubVulnDataSourceFactoryTest() {
        super(GitHubVulnDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeGitHub() {
        assertThat(factory.extensionName()).isEqualTo("github");
    }

    @Test
    void extensionClassShouldBeGitHubVulnDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(GitHubVulnDataSource.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final var config =
                (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(isEnabled);
        config.setApiToken("dummy");

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, configRegistry)
                .register(HttpClient.class, HttpClient.newHttpClient())
                .register(KeyValueStore.class, new MockKeyValueStore()));
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldThrowWhenDisabled() {
        final var config =
                (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, configRegistry)
                .register(HttpClient.class, HttpClient.newHttpClient())
                .register(KeyValueStore.class, new MockKeyValueStore()));

        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(factory::create);
    }

    @SuppressWarnings("unchecked")
    private void validate(final GithubVulnDataSourceConfigV1 config) {
        ((RuntimeConfigValidator<GithubVulnDataSourceConfigV1>)
                        factory.runtimeConfigSpec().validator())
                .validate(config);
    }

    private GithubVulnDataSourceConfigV1 enabledConfig() {
        return (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
    }

    @Test
    void validateShouldAcceptApiTokenOnly() {
        final var config = enabledConfig();
        config.setEnabled(true);
        config.setApiToken("pat");
        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldAcceptAppCredentials() {
        final var config = enabledConfig();
        config.setEnabled(true);
        config.setAppId("123");
        config.setInstallationId("42");
        config.setAppPrivateKey("-----BEGIN RSA PRIVATE KEY-----");
        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldRejectBothMethodsConfigured() {
        final var config = enabledConfig();
        config.setEnabled(true);
        config.setApiToken("pat");
        config.setAppId("123");
        config.setInstallationId("42");
        config.setAppPrivateKey("-----BEGIN RSA PRIVATE KEY-----");
        assertThatExceptionOfType(InvalidRuntimeConfigException.class).isThrownBy(() -> validate(config));
    }

    @Test
    void validateShouldRejectNoMethodConfigured() {
        final var config = enabledConfig();
        config.setEnabled(true);
        assertThatExceptionOfType(InvalidRuntimeConfigException.class).isThrownBy(() -> validate(config));
    }

    @Test
    void validateShouldRejectPartialAppCredentials() {
        final var config = enabledConfig();
        config.setEnabled(true);
        config.setAppId("123");
        assertThatExceptionOfType(InvalidRuntimeConfigException.class).isThrownBy(() -> validate(config));
    }

    @Test
    void validateShouldSkipWhenDisabled() {
        final var config = enabledConfig();
        config.setEnabled(false);
        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void createShouldReturnDataSource() {
        final var config =
                (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setApiToken("dummy");

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, configRegistry)
                .register(HttpClient.class, HttpClient.newHttpClient())
                .register(KeyValueStore.class, new MockKeyValueStore()));

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        dataSource.close();
    }

    @Test
    void shouldAuthenticateAgainstProxy(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(any(anyUrl())
                .inScenario("proxyAuth")
                .whenScenarioStateIs(STARTED)
                .willReturn(aResponse().withStatus(407).withHeader("Proxy-Authenticate", "Basic realm=\"proxy\""))
                .willSetStateTo("challenged"));
        stubFor(any(anyUrl())
                .inScenario("proxyAuth")
                .whenScenarioStateIs("challenged")
                .willReturn(okJson(/* language=JSON */ """
                    {
                      "data": {
                        "securityAdvisories": {
                          "nodes": [],
                          "totalCount": 0,
                          "pageInfo": {
                            "hasNextPage": false
                          }
                        }
                      }
                    }
                    """)));

        final var proxyAddress = new InetSocketAddress("localhost", wmRuntimeInfo.getHttpPort());
        final var proxySelector = new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return List.of(new Proxy(Proxy.Type.HTTP, proxyAddress));
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
        };
        final var authenticator = new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return getRequestorType() == RequestorType.PROXY
                        ? new PasswordAuthentication("proxyUser", "proxyPassword".toCharArray())
                        : null;
            }
        };

        final var config = enabledConfig();
        config.setEnabled(true);
        config.setApiToken("dummy");
        config.setApiUrl(URI.create("http://github.invalid/graphql"));

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                .register(
                        HttpClient.class,
                        HttpClient.newBuilder()
                                .proxy(proxySelector)
                                .authenticator(authenticator)
                                .build())
                .register(KeyValueStore.class, new MockKeyValueStore()));

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource.hasNext()).isFalse();
        dataSource.close();

        verify(postRequestedFor(anyUrl())
                .withHeader("Proxy-Authorization", equalTo("Basic cHJveHlVc2VyOnByb3h5UGFzc3dvcmQ=")));
    }
}
