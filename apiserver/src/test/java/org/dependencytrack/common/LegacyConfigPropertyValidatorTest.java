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

import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LegacyConfigPropertyValidatorTest {

    @Test
    void shouldNotFailWhenConfigIsEmpty() {
        assertThatCode(() -> LegacyConfigPropertyValidator.validate(new SmallRyeConfigBuilder().build()))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldNotFailWhenOnlyCanonicalV5Rc2PropertiesArePresent() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.cors.allowed-origins", "https://app.example.com")
                .withDefaultValue("dt.http.connect-timeout-ms", "30000")
                .withDefaultValue("dt.dex-engine.maintenance.run-retention-ms", "86400000")
                .withDefaultValue("dt.init-tasks.exit-after-completion", "false")
                .withDefaultValue("dt.ldap.bind-password", "secret")
                .build();

        assertThatCode(() -> LegacyConfigPropertyValidator.validate(config))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @MethodSource("legacyFileSecretProperties")
    void shouldFailWhenLegacyFileSecretPropertyIsPresent(final String legacyProperty) {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue(legacyProperty, "/path/to/secret")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Legacy file-secret properties are no longer supported")
                .hasMessageContaining(legacyProperty);
    }

    static Stream<String> legacyFileSecretProperties() {
        return LegacyConfigPropertyValidator.LEGACY_FILE_SECRET_PROPERTIES.stream();
    }

    @Test
    void shouldFailWhenAlpinePrefixedLegacyV4PropertyIsPresent() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.cors.allow.origin", "*")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Legacy Dependency-Track v4 configuration properties")
                .hasMessageContaining("alpine.cors.allow.origin");
    }

    @ParameterizedTest
    @MethodSource("legacyV5Rc1Renames")
    void shouldFailWhenLegacyV5Rc1PropertyIsPresent(final String oldName, final String newName) {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue(oldName, "value")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Legacy Dependency-Track v5.0.0-rc.1 configuration properties")
                .hasMessageContaining(oldName)
                .hasMessageContaining(newName);
    }

    static Stream<Arguments> legacyV5Rc1Renames() {
        return LegacyConfigPropertyValidator.LEGACY_V5_RC1_PROPERTY_RENAMES.entrySet().stream()
                .map(entry -> Arguments.of(entry.getKey(), entry.getValue()));
    }

    @Test
    void shouldListEveryOffendingV5Rc1PropertyInTheErrorMessage() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.cors.allow.origin", "*")
                .withDefaultValue("dt.http.timeout.connection", "30")
                .withDefaultValue("dt.init.and.exit", "true")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("dt.cors.allow.origin -> dt.cors.allowed-origins")
                .hasMessageContaining("dt.http.timeout.connection -> dt.http.connect-timeout-ms (now milliseconds, was seconds)")
                .hasMessageContaining("dt.init.and.exit -> dt.init-tasks.exit-after-completion");
    }

    @Test
    void shouldNotFailWhenCanonicalDtPropertyIsSetViaEnvVar() {
        final Config config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(Map.of(
                        "DT_TASK_TAG_MAINTENANCE_CRON", "1 * * * *",
                        "DT_LDAP_BIND_PASSWORD", "secret",
                        "DT_CORS_ALLOW_CREDENTIALS", "true"), 300))
                .build();

        assertThatCode(() -> LegacyConfigPropertyValidator.validate(config))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldFailOnLegacyV5Rc1EnvVarWhenEnvFormDoesNotCollideWithCanonical() {
        final Config config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(Map.of("DT_HTTP_TIMEOUT_CONNECTION", "30"), 300))
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("dt.http.timeout.connection -> dt.http.connect-timeout-ms");
    }

    @Test
    void shouldFailWhenUnprefixedLegacyV5Rc1PropertyIsPresent() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("vulnerability.policy.bundle.url", "https://example.com/bundle.zip")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("vulnerability.policy.bundle.url -> dt.vuln-policy-bundle.url");
    }

    @Test
    void shouldFailWhenUnprefixedLegacyV5Rc1PropertyIsSetViaEnvVar() {
        final Config config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(
                        Map.of("VULNERABILITY_POLICY_BUNDLE_URL", "https://example.com/bundle.zip"),
                        300))
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("vulnerability.policy.bundle.url -> dt.vuln-policy-bundle.url");
    }

    @Test
    void shouldStillFailOnLegacyV5Rc1PropertyFromPropertiesFileEvenWhenEnvFormCollides() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.task.tag.maintenance.cron", "1 * * * *")
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("dt.task.tag.maintenance.cron -> dt.task.tag-maintenance.cron");
    }

    @Test
    void shouldStillFailOnAlpinePrefixedEnvVar() {
        final Config config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(Map.of("ALPINE_BCRYPT_ROUNDS", "4"), 300))
                .build();

        assertThatThrownBy(() -> LegacyConfigPropertyValidator.validate(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("alpine.bcrypt.rounds");
    }

    @Test
    void shouldKeepEveryRenameEntryPointingAtDtPrefixedOldName() {
        assertThat(LegacyConfigPropertyValidator.LEGACY_V5_RC1_PROPERTY_RENAMES)
                .allSatisfy((oldName, newName) -> {
                    assertThat(oldName).startsWith("dt.");
                    assertThat(newName).isNotBlank();
                });
    }

}
