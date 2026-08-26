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
package org.dependencytrack.kevdatasource.vulncheck;

import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigValidator;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class VulnCheckKevDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull KevDataSource, @NonNull VulnCheckKevDataSourceFactory> {

    protected VulnCheckKevDataSourceFactoryTest() {
        super(VulnCheckKevDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeVulnCheck() {
        assertThat(factory.extensionName()).isEqualTo("vulncheck");
    }

    @Test
    void displayNameShouldSatisfyVulnCheckAttributionTerms() {
        // NB: VulnCheck's terms require the data to be labeled "VulnCheck KEV".
        // https://docs.vulncheck.com/community/vulncheck-kev/attribution
        assertThat(factory.displayName()).isEqualTo("VulnCheck KEV");
    }

    @Test
    void extensionClassShouldBeVulnCheckKevDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(VulnCheckKevDataSource.class);
    }

    @Test
    void defaultConfigShouldBeDisabled() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getApiUrl()).isEqualTo(URI.create("https://api.vulncheck.com"));
    }

    @Test
    void validateShouldAcceptDisabledConfigWithoutToken() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(false);

        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldAcceptEnabledConfigWithUrlAndToken() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);
        config.setApiToken("vulncheck_abc123");

        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldRejectEnabledConfigWithoutUrl() {
        final var config = new VulncheckKevDataSourceConfigV1()
                .withEnabled(true)
                .withApiToken("vulncheck_abc123");

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(() -> validate(config))
                .withMessageContaining("API URL");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    void validateShouldRejectEnabledConfigWithBlankToken(String apiToken) {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);
        config.setApiToken(apiToken);

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(() -> validate(config))
                .withMessageContaining("API token");
    }

    @Test
    void validateShouldRejectEnabledConfigWithoutToken() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(() -> validate(config))
                .withMessageContaining("API token");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isEnabledShouldReflectConfig(boolean isEnabled) {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(isEnabled);
        config.setApiToken("vulncheck_abc123");

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        assertThat(factory.isEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldThrowWhenDisabled() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(false);

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(factory::create);
    }

    @Test
    void createShouldReturnDataSourceWhenEnabled() {
        final VulncheckKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);
        config.setApiToken("vulncheck_abc123");

        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        try (final KevDataSource dataSource = factory.create()) {
            assertThat(dataSource).isInstanceOf(VulnCheckKevDataSource.class);
        }
    }

    private VulncheckKevDataSourceConfigV1 defaultRuntimeConfig() {
        return (VulncheckKevDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
    }

    @SuppressWarnings("unchecked")
    private void validate(VulncheckKevDataSourceConfigV1 config) {
        ((RuntimeConfigValidator<VulncheckKevDataSourceConfigV1>)
                factory.runtimeConfigSpec().validator()).validate(config);
    }

}
