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
package org.dependencytrack.plugin.testing;

import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * @since 5.0.0
 */
public abstract class AbstractExtensionFactoryTest<T extends ExtensionPoint, U extends ExtensionFactory<T>> {

    private final Class<U> factoryClass;
    protected U factory;

    protected AbstractExtensionFactoryTest(Class<U> factoryClass) {
        this.factoryClass = factoryClass;
    }

    @BeforeEach
    void beforeEach() throws Exception {
        final Constructor<U> constructor = factoryClass.getDeclaredConstructor();
        constructor.setAccessible(true);

        factory = constructor.newInstance();
    }

    @AfterEach
    void afterEach() {
        if (factory != null) {
            factory.close();
        }
    }

    @Test
    void shouldDefineExtensionName() {
        assertThat(factory.extensionName()).isNotBlank();
    }

    @Test
    void shouldDefineExtensionClass() {
        assertThat(factory.extensionClass()).isNotNull();
    }

    @Test
    void priorityShouldReturnZeroOrGreater() {
        assertThat(factory.priority()).isGreaterThanOrEqualTo(0);
    }

    @Nested
    class RuntimeConfigTest {

        @Test
        void shouldDefineSchema() {
            assumeThat(factory).isInstanceOf(RuntimeConfigurable.class);
            final RuntimeConfigSpec runtimeConfigSpec = ((RuntimeConfigurable) factory).runtimeConfigSpec();
            assertThat(runtimeConfigSpec).isNotNull();
            assertThat(runtimeConfigSpec.schema()).isNotNull();
        }

        @Test
        void shouldDefineValidDefaultConfigWhenSpecIsDefined() {
            assumeThat(factory).isInstanceOf(RuntimeConfigurable.class);
            final RuntimeConfigSpec runtimeConfigSpec = ((RuntimeConfigurable) factory).runtimeConfigSpec();
            assertThat(runtimeConfigSpec).isNotNull();

            final RuntimeConfig defaultConfig = runtimeConfigSpec.defaultConfig();
            assertThat(defaultConfig).isNotNull();

            assertThatNoException()
                    .isThrownBy(() -> RuntimeConfigMapper.getInstance().validate(
                            defaultConfig, runtimeConfigSpec));
        }

    }

}
