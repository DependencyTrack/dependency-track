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
package org.dependencytrack.vulndatasource.nvd;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class NvdVulnDataSourceTest {

    private NvdVulnDataSourceFactory dataSourceFactory;
    private VulnDataSource dataSource;

    @BeforeEach
    void beforeEach() {
        final var config = new NvdVulnDataSourceConfigV1();
        config.setEnabled(true);
        config.setCveFeedsUrl(URI.create("https://nvd.nist.gov/feeds"));

        dataSourceFactory = new NvdVulnDataSourceFactory();

        final var configRegistry = new MockConfigRegistry(dataSourceFactory.runtimeConfigSpec(), config);

        dataSourceFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));
        dataSource = dataSourceFactory.create();
    }

    @AfterEach
    void afterEach() {
        if (dataSource != null) {
            dataSource.close();
        }
        if (dataSourceFactory != null) {
            dataSourceFactory.close();
        }
    }

    @Test
    void test() {
        for (int i = 0; i < 5; i++) {
            assertThat(dataSource.hasNext()).isTrue();

            final Bom bov = dataSource.next();
            assertThat(bov).isNotNull();
            assertThat(bov.getVulnerabilitiesCount()).isEqualTo(1);

            final Vulnerability vuln = bov.getVulnerabilities(0);
            assertThat(vuln.getId()).startsWith("CVE-");
            assertThat(vuln.getSource().getName()).isEqualTo("NVD");
            assertThat(vuln.getDescription()).isNotEmpty();

            dataSource.markProcessed(bov);
        }
    }

    @Test
    void markProcessedShouldThrowWhenBovHasUnexpectedVulnCount() {
        final var bov = Bom.newBuilder()
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-123"))
                .addVulnerabilities(Vulnerability.newBuilder().setId("CVE-456"))
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dataSource.markProcessed(bov))
                .withMessage("BOV must have exactly one vulnerability, but has 2");
    }

}