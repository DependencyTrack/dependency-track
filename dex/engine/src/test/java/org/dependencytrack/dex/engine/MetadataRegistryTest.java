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
package org.dependencytrack.dex.engine;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

class MetadataRegistryTest {

    private static final Duration DEFAULT_LOCK_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration DEFAULT_EXECUTION_TIMEOUT = Duration.ofHours(1);

    private MetadataRegistry metadataRegistry;

    @BeforeEach
    void beforeEach() {
        metadataRegistry = new MetadataRegistry(DEFAULT_LOCK_TIMEOUT, DEFAULT_EXECUTION_TIMEOUT);
    }

    @Test
    void shouldApplyDefaultExecutionTimeoutWhenNoneIsProvided() {
        registerActivity("test", Duration.ofMinutes(1), /* executionTimeout */ null);

        assertThat(metadataRegistry.getActivityMetadata("test").executionTimeout())
                .isEqualTo(DEFAULT_EXECUTION_TIMEOUT);
    }

    @Test
    void shouldApplyDefaultLockTimeoutWhenNoneIsProvided() {
        registerActivity("test", /* lockTimeout */ null, /* executionTimeout */ null);

        assertThat(metadataRegistry.getActivityMetadata("test").lockTimeout())
                .isEqualTo(DEFAULT_LOCK_TIMEOUT);
    }

    @Test
    void shouldPreferProvidedLockTimeoutOverDefault() {
        registerActivity("test", Duration.ofMinutes(15), /* executionTimeout */ null);

        assertThat(metadataRegistry.getActivityMetadata("test").lockTimeout())
                .isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void shouldPreferProvidedExecutionTimeoutOverDefault() {
        registerActivity("test", Duration.ofMinutes(30), Duration.ofMinutes(45));

        assertThat(metadataRegistry.getActivityMetadata("test").executionTimeout())
                .isEqualTo(Duration.ofMinutes(45));
    }

    @Test
    void shouldRejectNonPositiveExecutionTimeout() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> registerActivity("test", Duration.ofMinutes(1), Duration.ZERO))
                .withMessageContaining("executionTimeout must be positive");
    }

    private void registerActivity(
            String name,
            @Nullable Duration lockTimeout,
            @Nullable Duration executionTimeout) {
        metadataRegistry.registerActivity(
                name,
                voidConverter(),
                voidConverter(),
                "default",
                lockTimeout,
                executionTimeout,
                (_, _) -> null);
    }

}
