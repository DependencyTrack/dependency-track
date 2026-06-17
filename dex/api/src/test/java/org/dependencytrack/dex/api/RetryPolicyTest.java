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
package org.dependencytrack.dex.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class RetryPolicyTest {

    @Test
    void shouldHaveExpectedDefaultPolicy() {
        final var defaultPolicy = RetryPolicy.ofDefault();
        assertThat(defaultPolicy.initialDelay()).hasSeconds(5);
        assertThat(defaultPolicy.delayMultiplier()).isEqualTo(1.5);
        assertThat(defaultPolicy.delayRandomizationFactor()).isEqualTo(0.3);
        assertThat(defaultPolicy.maxDelay()).hasMinutes(30);
        assertThat(defaultPolicy.maxAttempts()).isEqualTo(6);
    }

    @Test
    void shouldThrowWhenInitialDelayIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withInitialDelay(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void shouldThrowWhenInitialDelayIsNotPositive(final int delaySeconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withInitialDelay(Duration.ofSeconds(delaySeconds)));
    }

    @ParameterizedTest
    @ValueSource(doubles = {0, -1})
    void shouldThrowWhenMultiplierIsNotPositive(final double multiplier) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withDelayMultiplier(multiplier));
    }

    @ParameterizedTest
    @ValueSource(doubles = {0, -1})
    void shouldThrowWhenRandomizationFactorIsNotPositive(final double randomizationFactor) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withDelayRandomizationFactor(randomizationFactor));
    }

    @Test
    void shouldThrowWhenMaxDelayIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withMaxDelay(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void shouldThrowWhenMaxDelayIsNotPositive(final int delaySeconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withMaxDelay(Duration.ofSeconds(delaySeconds)));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void shouldThrowWhenMaxAttemptsIsNotPositive(final int maxAttempts) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> RetryPolicy.ofDefault().withMaxAttempts(maxAttempts));
    }

}