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
package org.dependencytrack.pkgmetadata.resolution.api;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class RetryableResolutionExceptionTest {

    @ParameterizedTest
    @ValueSource(longs = {-1, 0})
    @SuppressWarnings("ThrowableNotThrown")
    void shouldRejectNonPositiveRetryAfter(long seconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RetryableResolutionException(
                        null, null, Duration.of(seconds, ChronoUnit.SECONDS)));
    }

}
