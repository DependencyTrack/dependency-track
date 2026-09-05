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
package org.dependencytrack.kevdatasource.cisa;

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

class CisaKevDataSourceFactoryTest
        extends AbstractExtensionFactoryTest<@NonNull KevDataSource, @NonNull CisaKevDataSourceFactory> {

    protected CisaKevDataSourceFactoryTest() {
        super(CisaKevDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeCisa() {
        assertThat(factory.extensionName()).isEqualTo("cisa");
    }

    @Test
    void displayNameShouldBeCisaKev() {
        assertThat(factory.displayName()).isEqualTo("CISA KEV");
    }

    @Test
    void extensionClassShouldBeCisaKevDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(CisaKevDataSource.class);
    }

    @Test
    void defaultConfigShouldBeEnabled() {
        final CisaKevDataSourceConfigV1 config = defaultRuntimeConfig();

        assertThat(config.isEnabled()).isTrue();
        assertThat(config.getFeedUrl())
                .isEqualTo(URI.create(
                        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"));
    }

    @Test
    void validateShouldAcceptDisabledConfigWithoutFeedUrl() {
        final var config = new CisaKevDataSourceConfigV1().withEnabled(false);

        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldAcceptEnabledConfigWithFeedUrl() {
        final CisaKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);

        assertThatCode(() -> validate(config)).doesNotThrowAnyException();
    }

    @Test
    void validateShouldRejectEnabledConfigWithoutFeedUrl() {
        final var config = new CisaKevDataSourceConfigV1().withEnabled(true);

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(() -> validate(config))
                .withMessageContaining("feed URL");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isEnabledShouldReflectConfig(boolean isEnabled) {
        final CisaKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(isEnabled);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                .register(HttpClient.class, HttpClient.newHttpClient()));

        assertThat(factory.isEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldThrowWhenDisabled() {
        final CisaKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(false);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                .register(HttpClient.class, HttpClient.newHttpClient()));

        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(factory::create);
    }

    @Test
    void createShouldReturnDataSourceWhenEnabled() {
        final CisaKevDataSourceConfigV1 config = defaultRuntimeConfig();
        config.setEnabled(true);

        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                .register(HttpClient.class, HttpClient.newHttpClient()));

        try (final KevDataSource dataSource = factory.create()) {
            assertThat(dataSource).isInstanceOf(CisaKevDataSource.class);
        }
    }

    private CisaKevDataSourceConfigV1 defaultRuntimeConfig() {
        return (CisaKevDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
    }

    @SuppressWarnings("unchecked")
    private void validate(CisaKevDataSourceConfigV1 config) {
        ((RuntimeConfigValidator<CisaKevDataSourceConfigV1>)
                        factory.runtimeConfigSpec().validator())
                .validate(config);
    }
}
