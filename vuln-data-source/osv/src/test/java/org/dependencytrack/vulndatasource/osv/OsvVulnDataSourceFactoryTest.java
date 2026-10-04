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
package org.dependencytrack.vulndatasource.osv;

import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.ExtensionContextBuilder;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OsvVulnDataSourceFactoryTest
        extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull OsvVulnDataSourceFactory> {

    protected OsvVulnDataSourceFactoryTest() {
        super(OsvVulnDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeOsv() {
        assertThat(factory.extensionName()).isEqualTo("osv");
    }

    @Test
    void extensionClassShouldBeOsvVulnDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(OsvVulnDataSource.class);
    }

    @Test
    void priorityShouldBeZero() {
        assertThat(factory.priority()).isEqualTo(100);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final var config =
                (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(isEnabled);

        factory.init(new ExtensionContextBuilder()
                .withConfigRegistry(new MockConfigRegistry(factory.runtimeConfigSpec(), config))
                .build());
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldReturnNullWhenDisabled() {
        final var config =
                (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new ExtensionContextBuilder().withConfigRegistry(configRegistry).build());

        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(factory::create);
    }

    @Test
    void createShouldReturnDataSource() {
        final var config =
                (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new ExtensionContextBuilder().withConfigRegistry(configRegistry).build());

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        dataSource.close();
    }

    @Test
    void createWhenIncrementalMirroringDisabledShouldCreateDataSourceWithNullWatermarkManager() {
        final var config =
                (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new ExtensionContextBuilder().withConfigRegistry(configRegistry).build());

        try (VulnDataSource dataSource = factory.create()) {
            assertThat(dataSource).isNotNull();
            assertThat(((OsvVulnDataSource) dataSource).getWatermarkManager()).isNull();
        }
    }

    @Test
    void createWhenIncrementalMirroringEnabledShouldCreateDataSourceWithWatermarkManager() {
        final var config =
                (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(true);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(
                new ExtensionContextBuilder().withConfigRegistry(configRegistry).build());

        try (VulnDataSource dataSource = factory.create()) {
            assertThat(dataSource).isNotNull();
            assertThat(((OsvVulnDataSource) dataSource).getWatermarkManager()).isNotNull();
        }
    }
}
