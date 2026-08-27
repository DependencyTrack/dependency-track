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

import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Set;

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

    @Test
    void defaultConfigShouldContainSingleDefaultSource() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        assertThat(config.getSources()).satisfiesExactly(source -> {
            assertThat(source.getName()).isEqualTo("default");
            assertThat(source.isEnabled()).isFalse();
            assertThat(source.getAliasSyncEnabled()).isFalse();
            assertThat(source.isIncrementalMirroringEnabled()).isTrue();
            assertThat(source.getDataUrl().toString()).isEqualTo("https://storage.googleapis.com/osv-vulnerabilities");
            assertThat(source.getEcosystems()).containsExactlyInAnyOrder("npm", "PyPI", "NuGet", "Maven", "Go");
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> source.setEnabled(isEnabled));
        initFactory(config);
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldReturnNullWhenDisabled() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> source.setEnabled(false));
        initFactory(config);
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(factory::create);
    }

    @Test
    void createShouldReturnDataSource() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> source.setEnabled(true));
        initFactory(config);
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(((OsvCompositeVulnDataSource) dataSource).getDataSources()).hasSize(1);
        dataSource.close();
    }

    @Test
    void createShouldReturnDataSourcePerEnabledSource() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> source.setEnabled(true));
        config.getSources()
                .add(new OsvSourceConfigV1()
                        .withName("Chainguard")
                        .withEnabled(true)
                        .withIncrementalMirroringEnabled(true)
                        .withAliasSyncEnabled(false)
                        .withDataUrl(URI.create("https://chainguard.com/osv-vulnerabilities"))
                        .withEcosystems(Set.of("Maven")));
        config.getSources()
                .add(new OsvSourceConfigV1()
                        .withName("Red Hat")
                        .withEnabled(false)
                        .withIncrementalMirroringEnabled(false)
                        .withAliasSyncEnabled(false)
                        .withDataUrl(URI.create("https://redhat.com/osv-vulnerabilities"))
                        .withEcosystems(Set.of("Go")));
        initFactory(config);
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(((OsvCompositeVulnDataSource) dataSource).getDataSources()).hasSize(2);
        dataSource.close();
    }

    @Test
    void createWhenIncrementalMirroringDisabledShouldCreateDataSourceWithNullWatermarkManager() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> {
            source.setEnabled(true);
            source.setIncrementalMirroringEnabled(false);
        });
        initFactory(config);
        try (VulnDataSource dataSource = factory.create()) {
            assertThat(((OsvCompositeVulnDataSource) dataSource).getDataSources())
                    .singleElement()
                    .satisfies(
                            source -> assertThat(source.getWatermarkManager()).isNull());
        }
    }

    @Test
    void createWhenIncrementalMirroringEnabledShouldCreateDataSourceWithWatermarkManager() {
        final OsvVulnDataSourceConfigV1 config = defaultConfig();
        config.getSources().forEach(source -> {
            source.setEnabled(true);
            source.setIncrementalMirroringEnabled(true);
        });
        initFactory(config);
        try (VulnDataSource dataSource = factory.create()) {
            assertThat(((OsvCompositeVulnDataSource) dataSource).getDataSources())
                    .singleElement()
                    .satisfies(
                            source -> assertThat(source.getWatermarkManager()).isNotNull());
        }
    }

    private OsvVulnDataSourceConfigV1 defaultConfig() {
        return (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
    }

    private void initFactory(final OsvVulnDataSourceConfigV1 config) {
        initFactory(new MockConfigRegistry(factory.runtimeConfigSpec(), config));
    }

    private void initFactory(final ConfigRegistry configRegistry) {
        factory.init(new MutableServiceRegistry()
                .register(ConfigRegistry.class, configRegistry)
                .register(HttpClient.class, HttpClient.newHttpClient())
                .register(KeyValueStore.class, new MockKeyValueStore()));
    }
}
