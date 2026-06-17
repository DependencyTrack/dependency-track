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
package org.dependencytrack.plugin.runtime;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSchemaSource;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.config.RuntimeConfigSchemaValidationException;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ConfigRegistryImplTest extends AbstractDatabaseTest {

    private static final String EXTENSION_POINT = "test-extension-point";
    private static final String EXTENSION = "test-extension";

    private static final String SCHEMA_JSON = /* language=JSON */ """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "$id": "https://example.com/schema/test-config",
              "type": "object",
              "properties": {
                "url": {
                  "type": "string",
                  "format": "uri"
                },
                "token": {
                  "type": "string",
                  "x-secret-ref": true
                }
              },
              "additionalProperties": false,
              "required": ["url"]
            }
            """;

    private static final RuntimeConfigSpec CONFIG_SPEC = RuntimeConfigSpec.of(
            new TestConfig("https://example.com", null),
            new RuntimeConfigSchemaSource.Literal(SCHEMA_JSON),
            null);

    private static final RuntimeConfigSpec VALIDATING_CONFIG_SPEC = RuntimeConfigSpec.of(
            new TestConfig("https://example.com", null),
            new RuntimeConfigSchemaSource.Literal(SCHEMA_JSON),
            config -> {
                if ("https://forbidden.example.com".equals(config.url())) {
                    throw new InvalidRuntimeConfigException("URL is forbidden");
                }
            });

    private static final Config CONFIG = new SmallRyeConfigBuilder().build();

    private final RuntimeConfigMapper runtimeConfigMapper = RuntimeConfigMapper.getInstance();

    record TestConfig(
            @JsonProperty("url") String url,
            @JsonProperty("token") String token) implements RuntimeConfig {
    }

    @Test
    void shouldReturnEmptyWhenNoRuntimeConfigSpecProvided() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                null, null, null);

        assertThat(registry.getOptionalRuntimeConfig()).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenNoConfigExistsInDatabase() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThat(registry.getOptionalRuntimeConfig()).isEmpty();
    }

    @Test
    void shouldReturnRuntimeConfigWhenConfigExistsInDatabase() {
        seedConfig(/* language=JSON */ """
                {"url": "https://example.com"}
                """);

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        final var config = registry.getOptionalRuntimeConfig(TestConfig.class);
        assertThat(config).isPresent();
        assertThat(config.get().url()).isEqualTo("https://example.com");
    }

    @Test
    void shouldResolveSecretRefsWhenRetrievingRuntimeConfig() {
        seedConfig(/* language=JSON */ """
                {"url": "https://example.com", "token": "my-secret"}
                """);

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper,
                secretName -> "my-secret".equals(secretName) ? "resolved-value" : null);

        final var config = registry.getOptionalRuntimeConfig(TestConfig.class);
        assertThat(config).isPresent();
        assertThat(config.get().token()).isEqualTo("resolved-value");
    }

    @Test
    void shouldInvokeValidatorWhenRetrievingRuntimeConfig() {
        seedConfig(/* language=JSON */ """
                {"url": "https://forbidden.example.com"}
                """);

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                VALIDATING_CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(registry::getOptionalRuntimeConfig)
                .withMessage("URL is forbidden");
    }

    @Test
    void shouldSetRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        final boolean created = registry.setRuntimeConfig(new TestConfig("https://example.com", null));
        assertThat(created).isTrue();

        final var config = registry.getOptionalRuntimeConfig(TestConfig.class);
        assertThat(config).isPresent();
        assertThat(config.get().url()).isEqualTo("https://example.com");
    }

    @Test
    void shouldReturnFalseWhenSettingIdenticalRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThat(registry.setRuntimeConfig(new TestConfig("https://example.com", null))).isTrue();
        assertThat(registry.setRuntimeConfig(new TestConfig("https://example.com", null))).isFalse();
    }

    @Test
    void shouldRejectConfigOfWrongType() {
        record OtherConfig(String foo) implements RuntimeConfig {
        }

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> registry.setRuntimeConfig(new OtherConfig("bar")));
    }

    @Test
    void shouldValidateSchemaWhenSettingRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThatExceptionOfType(RuntimeConfigSchemaValidationException.class)
                .isThrownBy(() -> registry.setRuntimeConfig(new TestConfig(null, null)));
    }

    @Test
    void shouldInvokeValidatorWhenSettingRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                VALIDATING_CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                .isThrownBy(() -> registry.setRuntimeConfig(
                        new TestConfig("https://forbidden.example.com", null)))
                .withMessage("URL is forbidden");
    }

    @Test
    void shouldGetRawRuntimeConfig() {
        seedConfig(/* language=JSON */ """
                {"url": "https://example.com"}
                """);

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        final var rawConfig = registry.getRawRuntimeConfig();
        assertThat(rawConfig).isPresent();
        assertThat(rawConfig.get()).contains("https://example.com");
    }

    @Test
    void shouldReturnEmptyRawRuntimeConfigWhenNoneExists() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThat(registry.getRawRuntimeConfig()).isEmpty();
    }

    @Test
    void shouldSetRawRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        final boolean created = registry.setRawRuntimeConfig(/* language=JSON */ """
                {"url": "https://example.com"}
                """);
        assertThat(created).isTrue();

        assertThat(registry.getRawRuntimeConfig()).isPresent();
    }

    @Test
    void shouldReturnFalseWhenSettingIdenticalRawRuntimeConfig() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        final String configJson = /* language=JSON */ """
                {"url": "https://example.com"}
                """;
        assertThat(registry.setRawRuntimeConfig(configJson)).isTrue();
        assertThat(registry.setRawRuntimeConfig(configJson)).isFalse();
    }

    @Test
    void shouldReportHasRuntimeConfigFalseWhenNoSpec() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                null, null, null);

        assertThat(registry.hasRuntimeConfig()).isFalse();
    }

    @Test
    void shouldReportHasRuntimeConfigFalseWhenNoneExists() {
        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThat(registry.hasRuntimeConfig()).isFalse();
    }

    @Test
    void shouldReportHasRuntimeConfigTrueWhenExists() {
        seedConfig(/* language=JSON */ """
                {"url": "https://example.com"}
                """);

        final var registry = new ConfigRegistryImpl(
                jdbi, CONFIG, EXTENSION_POINT, EXTENSION,
                CONFIG_SPEC, runtimeConfigMapper, secretName -> null);

        assertThat(registry.hasRuntimeConfig()).isTrue();
    }

    private void seedConfig(String configJson) {
        jdbi.useHandle(handle ->
                new ExtensionConfigDao(handle).save(EXTENSION_POINT, EXTENSION, configJson));
    }

}