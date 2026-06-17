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
package org.dependencytrack.common.config;

import io.smallrye.config.ExpressionConfigSourceInterceptor;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class NamespacedConfigTest {

    @Test
    void shouldThrowWhenDelegateIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NamespacedConfig(null, "namespace"))
                .withMessage("delegate must not be null");
    }

    @Test
    void shouldThrowWhenNamespaceIsNull() {
        final var delegate = new SmallRyeConfigBuilder().build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NamespacedConfig(delegate, null))
                .withMessage("namespace must not be null");
    }

    @Test
    void shouldNamespaceConfigAccess() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("foo", "bar"),
                        Map.entry("foo.bar", "baz"),
                        Map.entry("foo.bar.baz", "qux"),
                        Map.entry("foo.bar.baz.qux", "quux")))
                .build();

        final Config namespacedConfig = new NamespacedConfig(config, "foo.bar");

        assertThat(namespacedConfig.getOptionalValue("foo", String.class)).isNotPresent();
        assertThat(namespacedConfig.getOptionalValue("foo.bar", String.class)).isNotPresent();
        assertThat(namespacedConfig.getOptionalValue("foo.bar.baz", String.class)).isNotPresent();
        assertThat(namespacedConfig.getOptionalValue("bar", String.class)).isNotPresent();
        assertThat(namespacedConfig.getOptionalValue("bar.baz", String.class)).isNotPresent();

        assertThat(namespacedConfig.getOptionalValue("baz", String.class)).contains("qux");
        assertThat(namespacedConfig.getOptionalValue("baz.qux", String.class)).contains("quux");
    }

    @Test
    void shouldResolveExpressionsToNonNamespacedConfigs() {
        final Config config = new SmallRyeConfigBuilder()
                .withInterceptors(new ExpressionConfigSourceInterceptor())
                .withDefaultValues(Map.ofEntries(
                        Map.entry("foo", "bar"),
                        Map.entry("foo.bar", "${foo}")))
                .build();
        assertThat(config.getOptionalValue("foo.bar", String.class)).contains("bar");

        final Config namespacedConfig = new NamespacedConfig(config, "foo");
        assertThat(namespacedConfig.getOptionalValue("bar", String.class)).contains("bar");
    }

    @Test
    void getPropertyNamesShouldReturnNamespacedNames() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("foo", "bar"),
                        Map.entry("foo.bar", "baz"),
                        Map.entry("foo.bar.baz", "qux"),
                        Map.entry("foo.bar.baz.qux", "quux")))
                .build();

        final Config namespacedConfig = new NamespacedConfig(config, "foo.bar");
        assertThat(namespacedConfig.getPropertyNames()).containsExactlyInAnyOrder("baz", "baz.qux");
    }

}