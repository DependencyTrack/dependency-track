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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.PackageURL;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.migration.MigrationExecutor;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.vulnanalysis.internal.InternalVulnAnalyzerTest.Range.withRange;

@Testcontainers
class InternalVulnAnalyzerTest {

    @Container
    private static final PostgreSQLContainer POSTGRES_CONTAINER =
            new PostgreSQLContainer("postgres:14-alpine");

    private static final boolean MATCHES = true;
    private static final boolean DOES_NOT_MATCH = false;
    private static final Range WITHOUT_RANGE = new Range(null, null, null, null);

    private static DataSourceRegistry dataSourceRegistry;

    private Jdbi jdbi;
    private InternalVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    @BeforeAll
    static void beforeAll() {
        dataSourceRegistry = new DataSourceRegistry(
                new SmallRyeConfigBuilder()
                        .withDefaultValue("dt.datasource.default.url", POSTGRES_CONTAINER.getJdbcUrl())
                        .withDefaultValue("dt.datasource.default.username", POSTGRES_CONTAINER.getUsername())
                        .withDefaultValue("dt.datasource.default.password", POSTGRES_CONTAINER.getPassword())
                        .build());

        new MigrationExecutor(dataSourceRegistry.getDefault()).execute();
    }

    @BeforeEach
    void beforeEach() {
        jdbi = Jdbi.create(dataSourceRegistry.getDefault());

        final var configRegistry = new MockConfigRegistry(
                Map.of("datasource.name", "default"));

        analyzerFactory = new InternalVulnAnalyzerFactory(dataSourceRegistry);
        analyzerFactory.init(new MutableServiceRegistry().register(ConfigRegistry.class, configRegistry));

        analyzer = analyzerFactory.create();
    }

    @AfterEach
    void afterEach() {
        if (analyzer != null) {
            analyzer.close();
        }
        if (analyzerFactory != null) {
            analyzerFactory.close();
        }
        if (jdbi != null) {
            jdbi.useTransaction(handle -> {
                handle.execute("TRUNCATE TABLE \"VULNERABLESOFTWARE_VULNERABILITIES\" CASCADE");
                handle.execute("TRUNCATE TABLE \"VULNERABILITY\" CASCADE");
                handle.execute("TRUNCATE TABLE \"VULNERABLESOFTWARE\" CASCADE");
            });
        }
    }

    @AfterAll
    static void afterAll() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Nested
    class CpeMatchingTest {

        private static Collection<Arguments> parameters() {
            return Arrays.asList(
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 1   | ANY        | ANY        | EQUAL    |
                    Arguments.of("cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 2   | ANY        | NA         | SUPERSET |
                    Arguments.of("cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 3   | ANY        | i          | SUPERSET |
                    Arguments.of("cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // | No. | Source A-V | Target A-V     | Relation   |
                    // | :-- | :--------- | :------------- | :--------- |
                    // | 4   | ANY        | m + wild cards | undefined  |
                    // {"cpe:2.3:*:vendor:product:1.0.0:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 5   | NA         | ANY        | SUBSET   |
                    Arguments.of("cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 6   | NA         | NA         | EQUAL    |
                    Arguments.of("cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 7   | NA         | i          | DISJOINT |
                    Arguments.of("cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // | No. | Source A-V | Target A-V      | Relation   |
                    // | :-- | :--------- | :-------------- | :--------- |
                    // | 8   | NA         | m + wild cards  | undefined  |
                    // {"cpe:2.3:-:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 9   | i          | i          | EQUAL    |
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 10  | i          | k          | DISJOINT |
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:o:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:rodnev:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:tcudorp:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:0.0.1:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:etadpu:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:noitide:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:gnal:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:noitidEws:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:wStegrat:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:wHtegrat:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:rehto"),
                    // | No. | Source A-V | Target A-V      | Relation   |
                    // | :-- | :--------- | :-------------- | :--------- |
                    // | 11  | i          | m + wild cards  | undefined  |
                    // {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"),
                    // | No. | Source A-V | Target A-V | Relation |
                    // | :-- | :--------- | :--------- | :------- |
                    // | 12  | i          | NA         | DISJOINT |
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"),
                    // | No. | Source A-V     | Target A-V | Relation |
                    // | :-- | :------------- | :--------- | :------- |
                    // | 13  | i              | ANY        | SUPERSET |
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"),
                    // | No. | Source A-V      | Target A-V | Relation             |
                    // | :-- | :-------------- | :--------- | :------------------- |
                    // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
                    // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    //   wildcard expansion in source vendor is currently not supported; *should* be SUPERSET.
                    Arguments.of("cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    //   wildcard expansion in source product is currently not supported; *should* be SUPERSET.
                    Arguments.of("cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // | No. | Source A-V     | Target A-V | Relation |
                    // | :-- | :------------- | :--------- | :------- |
                    // | 15  | m + wild cards | ANY        | SUPERSET |
                    // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:*:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"),
                    // | No. | Source A-V     | Target A-V | Relation |
                    // | :-- | :------------- | :--------- | :------- |
                    // | 16  | m + wild cards | NA         | DISJOINT |
                    // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:-:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"),
                    // | No. | Source A-V      | Target A-V      | Relation   |
                    // | :-- | :-------------- | :-------------- | :--------- |
                    // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
                    // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    //   cpe-parser library does not allow wildcards for the part attribute.
                    Arguments.of("cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"),
                    Arguments.of("cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:v*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:p*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1*:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:u*:edition:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:e*:lang:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:l*:swEdition:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:s*:targetSw:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:t*:targetHw:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:t*:other"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:o*"),
                    // ---
                    // Version range evaluation
                    // ---
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("1.0.0"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartExcluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("0.9.9"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartExcluding("0.9.9"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.0"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndExcluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.1"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndExcluding("1.0.1"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"),
                    // ---
                    // Required CPE name comparison relations (as per table 6-4 in the spec)
                    // ---
                    // Scenario:  All attributes are EQUAL
                    Arguments.of("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:-:-:-:-:-:-:-:-:-:-:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:-:-:-:-:-:-:-:-:-:-"),
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // Scenario:  All attributes of source are SUPERSET of target
                    Arguments.of("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"),
                    // Scenario:  All attributes of source are SUBSET of target
                    Arguments.of("cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"),
                    // ---
                    // Regression tests
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/1320
                    // Scenario:  "product" of source is "2000e_firmware", "version" of target is "2000e_firmware" -> EQUAL.
                    //            "version" of source is NA, "version" of target is NA -> EQUAL.
                    // Table No.: 6, 9
                    Arguments.of("cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*"),
                    // Scenario:  "version" of source is ANY, "version" of target is "2000e" -> SUPERSET.
                    //            "update" of source is ANY, "update" of target is NA -> SUPERSET.
                    // Table No.: 3, 2
                    Arguments.of("cpe:2.3:h:intel:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:h:intel:2000e:-:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/1832
                    // Scenario:  "version" of source is NA, "version" of target is "2.4.54" -> DISJOINT.
                    // Table No.: 7
                    Arguments.of("cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"),
                    // Scenario:  "version" of source is NA, "version" of target is ANY -> SUBSET.
                    // Table No.: 5
                    Arguments.of("cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2188
                    // Scenario:  "update" of source is NA, "update" of target is ANY -> SUBSET.
                    // Table No.: 5
                    Arguments.of("cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:xiph:speex:1.2:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2580
                    // Scenario:  "vendor" of source is "linux", "vendor" of target ANY -> SUBSET.
                    // Table No.: 13
                    Arguments.of("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:*:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:4.19.139:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2894
                    // Scenario:  "vendor" and "product" with different casing -> EQUAL.
                    // Table No.: 9
                    // Note:      CPEs with uppercase "part" are considered invalid by the cpe-parser library.
                    // TODO:      This should match, but can't currently support this as it would require an function index on UPPER("PART"),
                    //            UPPER("VENDOR"), and UPPER("PRODUCT"), which we cannot add through JDO annotations.
                    Arguments.of("cpe:2.3:o:lInUx:lInUx_KeRnEl:5.15.37:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:LiNuX:LiNuX_kErNeL:5.15.37:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2988
                    // Scenario:  "other" attribute of source is NA, "other" attribute of target is ANY -> SUBSET.
                    // Table No.: 5
                    Arguments.of("cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:NA", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"),
                    // Scenario:  "target_hw" of source if x64, "target_hw" of target is ANY -> SUBSET.
                    // Table No.: 13
                    Arguments.of("cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:x86:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"),
                    // Scenario:  "vendor" of source contains wildcard, "vendor" of target is ANY -> SUBSET.
                    // Table No.: 15
                    Arguments.of("cpe:2.3:o:linu*:linux_kernel:5.15.37:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:5.15.37:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2994
                    // Scenario:  "part" of source is "a", "part" of target is ANY -> SUBSET.
                    // Table No.: 13
                    Arguments.of("cpe:2.3:a:busybox:busybox:1.34.1:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:busybox:busybox:1.34.1:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/pull/1929#issuecomment-1759411976
                    // Scenario:  "part" and "vendor" of source are i, "part" and "vendor" of target are ANY -> SUBSET
                    // Table No.: 13
                    Arguments.of("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:nginx:*:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", withRange().havingEndExcluding("1.21.0"), MATCHES, "cpe:2.3:*:*:nginx:*:*:*:*:*:*:*:*"),
                    // Scenario:  Same as above, but "version" of target is i, which evaluates to SUPERSET for the "version" attribute
                    // Table No.: 3, 13
                    Arguments.of("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:nginx:1.20.1:*:*:*:*:*:*:*"),
                    Arguments.of("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", withRange().havingEndExcluding("1.21.0"), MATCHES, "cpe:2.3:*:*:nginx:1.20.1:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/3178#issuecomment-1812809295
                    // Scenario:  "vendor" of source is i, "product" of source is ANY, "vendor" of target is ANY, "product" of target is i
                    //            We consider mixed SUBSET and SUPERSET relations in "vendor" and "product" attributes to be ambiguous and treat them as no-match
                    // Table No.: 3, 13
                    Arguments.of("cpe:2.3:a:pascom_cloud_phone_system:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:*:util-linux-setarch:2.37.4:*:*:*:*:*:*:*"),
                    // ---
                    // Issue:     https://github.com/DependencyTrack/dependency-track/issues/4609
                    // Scenario:  "version" of source and target are ANY -> EQUAL.
                    //            A version range is available but doesn't make sense to use since the target version is already ANY.
                    // Table No.: 1
                    Arguments.of("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", withRange().havingStartIncluding("1.2.0").havingEndExcluding("1.2.9"), MATCHES, "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"),
                    // Scenario:  Same as above, but "version" of target is NA -> SUPERSET.
                    // Table No.: 2
                    Arguments.of("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", withRange().havingStartIncluding("1.2.0").havingEndExcluding("1.2.9"), MATCHES, "cpe:2.3:a:zlib:zlib:-:*:*:*:*:*:*:*"));
        }

        @ParameterizedTest
        @MethodSource("parameters")
        void test(
                String sourceCpe,
                Range sourceRange,
                boolean expectMatch,
                String targetCpe) throws Exception {
            jdbi.useTransaction(handle -> {
                final long vulnDbId = createVulnerability(handle);
                createCpeVulnerableSoftware(handle, sourceCpe, sourceRange, vulnDbId);
            });

            final var bom = Bom.newBuilder()
                    .addComponents(
                            Component.newBuilder()
                                    .setBomRef("1")
                                    .setName("acme-lib")
                                    .setCpe(targetCpe)
                                    .build())
                    .build();

            final Bom vdr = analyzer.analyze(bom);

            if (expectMatch) {
                assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
            } else {
                assertThat(vdr.getVulnerabilitiesList()).isEmpty();
            }
        }

    }

    @Nested
    class PurlMatchingTest {

        private static Collection<Arguments> parameters() {
            return Arrays.asList(
                    Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources", WITHOUT_RANGE, MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"),
                    Arguments.of("pkg:npm/foobar@12.3.1", WITHOUT_RANGE, MATCHES, "pkg:npm/foobar@12.3.1"),
                    Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim", WITHOUT_RANGE, MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"),
                    Arguments.of("pkg:npm/foobar", WITHOUT_RANGE, MATCHES, "pkg:npm/foobar@12.3.1"),
                    Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim", Range.withRange().havingStartIncluding("1.5.0").havingEndExcluding("2.0.0"), MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.8.0"),
                    Arguments.of("pkg:npm/foobar", Range.withRange().havingStartExcluding("10.0.0").havingEndIncluding("15.0.0"), MATCHES, "pkg:npm/foobar@12.3.1"),
                    Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1", WITHOUT_RANGE, DOES_NOT_MATCH, "pkg:npm/org.apache.xmlgraphics/batik-anim@1.9.1"),
                    Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1", WITHOUT_RANGE, DOES_NOT_MATCH, "pkg:maven/com.example/batik-anim@1.9.1"),
                    Arguments.of("pkg:nuget/System.IO.Packaging", withRange().havingStartIncluding("8.0.0-preview.1.23110.8").havingEndIncluding("8.0.0"), MATCHES, "pkg:nuget/System.IO.Packaging@8.0.0"),
                    Arguments.of("pkg:nuget/System.IO.Packaging", withRange().havingStartIncluding("8.0.0-preview.1.23110.8").havingEndIncluding("8.0.0"), DOES_NOT_MATCH, "pkg:nuget/System.IO.Packaging@8.0.1"),
                    Arguments.of("pkg:composer/typo3/cms-backend", withRange().havingStartIncluding("4.1.0").havingEndExcluding("4.1.13"), DOES_NOT_MATCH, "pkg:composer/typo3/cms-backend@v12.4.44"),
                    Arguments.of("pkg:composer/typo3/cms-backend", withRange().havingStartIncluding("4.3alpha1").havingEndExcluding("4.3beta2"), MATCHES, "pkg:composer/typo3/cms-backend@4.3beta1"),
                    Arguments.of("pkg:composer/typo3/cms-backend", withRange().havingStartIncluding("4.3alpha1").havingEndExcluding("4.3beta2"), DOES_NOT_MATCH, "pkg:composer/typo3/cms-backend@4.3.0"),
                    Arguments.of("pkg:deb/debian/busybox?arch=source&distro=debian-13", withRange().havingEndExcluding("1:1.37.0-1"), DOES_NOT_MATCH, "pkg:deb/debian/busybox@1.37.0-6%2Bb7?arch=amd64&distro=debian-13.4&epoch=1"),
                    Arguments.of("pkg:rpm/redhat/openssl", withRange().havingEndExcluding("1:1.1.1k-7"), DOES_NOT_MATCH, "pkg:rpm/redhat/openssl@1.1.1k-8?epoch=1"));
        }


        @ParameterizedTest(name = "[{index}] expect={2} src={0} range={1} target={3}")
        @MethodSource("parameters")
        void test(
                String sourcePurlString,
                Range sourceRange,
                boolean expectMatch,
                String targetPurlString) throws Exception {
            jdbi.useTransaction(handle -> {
                final long vulnDbId = createVulnerability(handle);
                createPurlVulnerableSoftware(handle, sourcePurlString, sourceRange, vulnDbId);
            });

            final var bom = Bom.newBuilder()
                    .addComponents(
                            Component.newBuilder()
                                    .setBomRef("1")
                                    .setName("acme-lib")
                                    .setPurl(targetPurlString)
                                    .build())
                    .build();

            final Bom vdr = analyzer.analyze(bom);

            if (expectMatch) {
                assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
            } else {
                assertThat(vdr.getVulnerabilitiesList()).isEmpty();
            }
        }

    }

    @Nested
    class DistroMatchingTest {

        private static final Range RANGE = Range.withRange().havingEndExcluding("2.0.0");

        private static Collection<Arguments> parameters() {
            return Arrays.asList(
                    // ---
                    // Debian
                    // ---
                    // Scenario: Same distro qualifier string
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                    // Scenario: Codename vs version (semantic match)
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=bullseye"),
                    // Scenario: Version vs codename
                    Arguments.of("pkg:deb/debian/sudo?distro=bullseye", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                    // Scenario: Point release vs major version
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11.6"),
                    // Scenario: Different Debian versions
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=debian-12"),
                    // Scenario: Different Debian codenames
                    Arguments.of("pkg:deb/debian/sudo?distro=bullseye", RANGE, DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=bookworm"),
                    // ---
                    // Ubuntu
                    // ---
                    // Scenario: Same Ubuntu version
                    Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, MATCHES, "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"),
                    // Scenario: Ubuntu codename vs version
                    Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, MATCHES, "pkg:deb/ubuntu/sudo@1.9.5?distro=jammy"),
                    // Scenario: Different Ubuntu versions
                    Arguments.of("pkg:deb/ubuntu/sudo?distro=ubuntu-22.04", RANGE, DOES_NOT_MATCH, "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04"),
                    // ---
                    // Alpine
                    // ---
                    // Scenario: Same Alpine version
                    Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, MATCHES, "pkg:apk/alpine/curl@1.0.0?distro=alpine-3.16"),
                    // Scenario: Alpine point release vs major.minor
                    Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, MATCHES, "pkg:apk/alpine/curl@1.0.0?distro=3.16.4"),
                    // Scenario: Different Alpine versions
                    Arguments.of("pkg:apk/alpine/curl?distro=alpine-3.16", RANGE, DOES_NOT_MATCH, "pkg:apk/alpine/curl@1.0.0?distro=alpine-3.18"),
                    // ---
                    // One side missing distro
                    // ---
                    // Scenario: VS has distro, component does not
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5"),
                    // Scenario: Component has distro, VS does not
                    Arguments.of("pkg:deb/debian/sudo", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                    // Scenario: Neither has distro
                    Arguments.of("pkg:deb/debian/sudo", RANGE, MATCHES, "pkg:deb/debian/sudo@1.9.5"),
                    // ---
                    // Distro match does not bypass version check
                    // ---
                    // Scenario: Distro matches but version out of range
                    Arguments.of("pkg:deb/debian/sudo?distro=debian-11", Range.withRange().havingEndExcluding("1.0.0"), DOES_NOT_MATCH, "pkg:deb/debian/sudo@1.9.5?distro=debian-11"),
                    // ---
                    // Unsupported PURL type with distro qualifiers
                    // ---
                    // Scenario: Both have distro, neither parseable, same string
                    Arguments.of("pkg:rpm/redhat/sudo?distro=el-9", RANGE, MATCHES, "pkg:rpm/redhat/sudo@1.9.5?distro=el-9"),
                    // Scenario: Both have distro, neither parseable, different strings (mismatch)
                    Arguments.of("pkg:rpm/redhat/sudo?distro=rhel-9", RANGE, DOES_NOT_MATCH, "pkg:rpm/redhat/sudo@1.9.5?distro=el-9"));
        }

        @ParameterizedTest(name = "[{index}] expect={2} src={0} target={3}")
        @MethodSource("parameters")
        void shouldMatchDistroQualifier(
                String sourcePurlString,
                Range sourceRange,
                boolean expectMatch,
                String targetPurlString) throws Exception {
            jdbi.useTransaction(handle -> {
                final long vulnDbId = createVulnerability(handle);
                createPurlVulnerableSoftware(handle, sourcePurlString, sourceRange, vulnDbId);
            });

            final var bom = Bom.newBuilder()
                    .addComponents(
                            Component.newBuilder()
                                    .setBomRef("1")
                                    .setName("acme-lib")
                                    .setPurl(targetPurlString)
                                    .build())
                    .build();

            final Bom vdr = analyzer.analyze(bom);

            if (expectMatch) {
                assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
            } else {
                assertThat(vdr.getVulnerabilitiesList()).isEmpty();
            }
        }

    }

    @Test
    void shouldNotSkipPurlAnalysisWhenCpeIsInvalid() throws Exception {
        jdbi.useTransaction(handle -> {
            final long vulnDbId = createVulnerability(handle, "GHSA-0000-0000-0001", "GITHUB");
            createPurlVulnerableSoftware(
                    handle,
                    "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
                    Range.withRange().havingEndExcluding("2.13.1"),
                    vulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jackson-databind")
                        .setCpe("cpe:invalid")
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
        assertThat(vdr.getVulnerabilitiesList().getFirst().getId()).isEqualTo("GHSA-0000-0000-0001");
    }

    @Test
    void shouldMatchOnBothCpeAndPurlWhenComponentHasBoth() throws Exception {
        jdbi.useTransaction(handle -> {
            final long cveVulnDbId = createVulnerability(handle, "CVE-2022-00001", "NVD");
            createCpeVulnerableSoftware(
                    handle,
                    "cpe:2.3:a:fasterxml:jackson-databind:2.13.0:*:*:*:*:*:*:*",
                    WITHOUT_RANGE,
                    cveVulnDbId);

            final long ghsaVulnDbId = createVulnerability(handle, "GHSA-0000-0000-0001", "GITHUB");
            createPurlVulnerableSoftware(
                    handle,
                    "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
                    Range.withRange().havingEndExcluding("2.13.1"),
                    ghsaVulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("jackson-databind")
                        .setCpe("cpe:2.3:a:fasterxml:jackson-databind:2.13.0:*:*:*:*:*:*:*")
                        .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList())
                .extracting(Vulnerability::getId)
                .containsExactlyInAnyOrder("CVE-2022-00001", "GHSA-0000-0000-0001");
    }

    @Test
    void shouldUseCpeVersionNotComponentVersionForCpeMatching() throws Exception {
        jdbi.useTransaction(handle -> {
            final long vulnDbId = createVulnerability(handle, "CVE-2023-00001", "NVD");
            createCpeVulnerableSoftware(
                    handle,
                    "cpe:2.3:o:st:stm32l4_firmware:-:*:*:*:*:*:*:*",
                    WITHOUT_RANGE,
                    vulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("stm32l4_firmware")
                        .setVersion("1.2.3")
                        .setCpe("cpe:2.3:o:st:stm32l4_firmware:-:*:*:*:*:*:*:*")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
        assertThat(vdr.getVulnerabilitiesList().getFirst().getId()).isEqualTo("CVE-2023-00001");
    }

    @Test
    void shouldNotMatchWhenCpeVersionOutsideRangeEvenIfComponentVersionInRange() throws Exception {
        jdbi.useTransaction(handle -> {
            final long vulnDbId = createVulnerability(handle, "CVE-2023-00002", "NVD");
            createCpeVulnerableSoftware(
                    handle,
                    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    Range.withRange().havingStartIncluding("1.0.0").havingEndExcluding("2.0.0"),
                    vulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("product")
                        .setVersion("1.5.0")
                        .setCpe("cpe:2.3:a:vendor:product:5.0:*:*:*:*:*:*:*")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList()).isEmpty();
    }

    @Test
    void shouldUsePurlVersionNotComponentVersionForPurlMatching() throws Exception {
        jdbi.useTransaction(handle -> {
            final long vulnDbId = createVulnerability(handle, "CVE-2023-00003", "NVD");
            createPurlVulnerableSoftware(
                    handle,
                    "pkg:maven/com.example/lib",
                    Range.withRange().havingEndExcluding("1.0.1"),
                    vulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("lib")
                        .setVersion("2.0.0")
                        .setPurl("pkg:maven/com.example/lib@1.0.0")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
        assertThat(vdr.getVulnerabilitiesList().getFirst().getId()).isEqualTo("CVE-2023-00003");
    }

    @Test
    void shouldNotMatchWhenPurlHasNoVersion() throws Exception {
        jdbi.useTransaction(handle -> {
            final long vulnDbId = createVulnerability(handle, "CVE-2023-00005", "NVD");
            createPurlVulnerableSoftware(
                    handle,
                    "pkg:maven/com.example/lib",
                    Range.withRange().havingEndExcluding("2.0.0"),
                    vulnDbId);
        });

        final var bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("lib")
                        .setVersion("1.0.0")
                        .setPurl("pkg:maven/com.example/lib")
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);

        assertThat(vdr.getVulnerabilitiesList()).isEmpty();
    }

    public record Range(String startIncluding, String startExcluding, String endIncluding, String endExcluding) {

        public static Range withRange() {
            return new Range(null, null, null, null);
        }

        public Range havingStartIncluding(final String startIncluding) {
            return new Range(startIncluding, this.startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingStartExcluding(final String startExcluding) {
            return new Range(this.startIncluding, startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingEndIncluding(final String endIncluding) {
            return new Range(this.startIncluding, this.startExcluding, endIncluding, this.endExcluding);
        }

        public Range havingEndExcluding(final String endExcluding) {
            return new Range(this.startIncluding, this.startExcluding, this.endIncluding, endExcluding);
        }

    }

    private long createVulnerability(Handle handle) {
        return createVulnerability(handle, "CVE-123", "NVD");
    }

    private long createVulnerability(Handle handle, String vulnId, String source) {
        return handle
                .createUpdate("""
                        INSERT INTO "VULNERABILITY" ("VULNID", "SOURCE", "UUID")
                        VALUES (:vulnId, :source, GEN_RANDOM_UUID())
                        RETURNING "ID"
                        """)
                .bind("vulnId", vulnId)
                .bind("source", source)
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .one();
    }

    private static void createCpeVulnerableSoftware(Handle handle, String cpe23, Range range, long vulnDbId) throws Exception {
        final Cpe cpe = CpeParser.parse(cpe23);

        final long vsId = handle
                .createUpdate("""
                        INSERT INTO "VULNERABLESOFTWARE" (
                          "CPE23"
                        , "PART"
                        , "VENDOR"
                        , "PRODUCT"
                        , "VERSION"
                        , "UPDATE"
                        , "EDITION"
                        , "LANGUAGE"
                        , "SWEDITION"
                        , "TARGETSW"
                        , "TARGETHW"
                        , "OTHER"
                        , "VERSIONSTARTINCLUDING"
                        , "VERSIONSTARTEXCLUDING"
                        , "VERSIONENDEXCLUDING"
                        , "VERSIONENDINCLUDING"
                        , "VULNERABLE"
                        , "UUID"
                        ) VALUES (
                          :cpe23
                        , LOWER(:cpe.part.abbreviation)
                        , LOWER(:cpe.vendor)
                        , LOWER(:cpe.product)
                        , :cpe.version
                        , :cpe.update
                        , :cpe.edition
                        , :cpe.language
                        , :cpe.swEdition
                        , :cpe.targetSw
                        , :cpe.targetHw
                        , :cpe.other
                        , :range.startIncluding
                        , :range.startExcluding
                        , :range.endExcluding
                        , :range.endIncluding
                        , TRUE
                        , GEN_RANDOM_UUID()
                        )
                        RETURNING "ID"
                        """)
                .bind("cpe23", cpe23)
                .bindBean("cpe", cpe)
                .bindMethods("range", range)
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .one();

        handle
                .createUpdate("""
                        INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                        VALUES (:vulnId, :vsId)
                        """)
                .bind("vulnId", vulnDbId)
                .bind("vsId", vsId)
                .execute();
    }

    private static void createPurlVulnerableSoftware(Handle handle, String purlStr, Range range, long vulnDbId) throws Exception {
        final var purl = new PackageURL(purlStr);

        final long vsId = handle
                .createUpdate("""
                        INSERT INTO "VULNERABLESOFTWARE" (
                          "PURL"
                        , "PURL_TYPE"
                        , "PURL_NAMESPACE"
                        , "PURL_NAME"
                        , "VERSION"
                        , "VERSIONSTARTINCLUDING"
                        , "VERSIONSTARTEXCLUDING"
                        , "VERSIONENDEXCLUDING"
                        , "VERSIONENDINCLUDING"
                        , "VULNERABLE"
                        , "UUID"
                        ) VALUES (
                          :purlStr
                        , :purl.type
                        , :purl.namespace
                        , :purl.name
                        , :purl.version
                        , :range.startIncluding
                        , :range.startExcluding
                        , :range.endExcluding
                        , :range.endIncluding
                        , TRUE
                        , GEN_RANDOM_UUID()
                        )
                        RETURNING "ID"
                        """)
                .bind("purlStr", purlStr)
                .bindBean("purl", purl)
                .bindMethods("range", range)
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .one();

        handle
                .createUpdate("""
                        INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                        VALUES (:vulnId, :vsId)
                        """)
                .bind("vulnId", vulnDbId)
                .bind("vsId", vsId)
                .execute();
    }

}