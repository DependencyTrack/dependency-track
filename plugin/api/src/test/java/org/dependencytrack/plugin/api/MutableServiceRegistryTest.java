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
package org.dependencytrack.plugin.api;

import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class MutableServiceRegistryTest {

    @Test
    void shouldRegisterAndGetService() {
        final var registry = new MutableServiceRegistry()
                .register(String.class, "foo")
                .freeze();

        assertThat(registry.get(String.class)).contains("foo");
    }

    @Test
    void shouldReturnEmptyForUnregisteredService() {
        final var registry = new MutableServiceRegistry().freeze();

        assertThat(registry.get(String.class)).isEmpty();
    }

    @Test
    void shouldRequireRegisteredService() {
        final var registry = new MutableServiceRegistry()
                .register(String.class, "foo")
                .freeze();

        assertThat(registry.require(String.class)).isEqualTo("foo");
    }

    @Test
    void shouldThrowOnRequireForUnregisteredService() {
        final var registry = new MutableServiceRegistry().freeze();

        assertThatExceptionOfType(NoSuchElementException.class)
                .isThrownBy(() -> registry.require(String.class))
                .withMessageContaining("java.lang.String");
    }

    @Test
    void shouldRejectDuplicateRegistration() {
        final var registry = new MutableServiceRegistry()
                .register(String.class, "foo");

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> registry.register(String.class, "bar"))
                .withMessageContaining("java.lang.String");
    }

    @Test
    void shouldRejectRegistrationAfterFreeze() {
        final var registry = new MutableServiceRegistry().freeze();

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> registry.register(String.class, "foo"))
                .withMessageContaining("frozen");
    }

    @Test
    void shouldRejectNullType() {
        final var registry = new MutableServiceRegistry();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> registry.register(null, "foo"))
                .withMessage("type must not be null");
    }

    @Test
    void shouldRejectNullService() {
        final var registry = new MutableServiceRegistry();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> registry.register(String.class, null))
                .withMessage("service must not be null");
    }

    @Test
    void shouldRejectNullTypeOnGet() {
        final var registry = new MutableServiceRegistry().freeze();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> registry.get(null))
                .withMessage("type must not be null");
    }

}
