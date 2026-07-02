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

import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class GitHubVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull GitHubVulnDataSourceFactory> {

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
        final var config = (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(isEnabled);
        config.setApiToken("dummy");

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldThrowWhenDisabled() {
        final var config = (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(factory::create);
    }

    @SuppressWarnings("unchecked")
    private void validate(final GithubVulnDataSourceConfigV1 config) {
        ((RuntimeConfigValidator<GithubVulnDataSourceConfigV1>) factory.runtimeConfigSpec().validator())
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
        final var config = (GithubVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setApiToken("dummy");

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        dataSource.close();
    }

}