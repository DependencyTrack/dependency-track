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
package org.dependencytrack.policy;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class PolicyEvaluationDeadlineTest {

    @Test
    void invokesHeartbeatBeforeDeadline() {
        final var now = new AtomicReference<>(Instant.parse("2024-01-01T00:00:00Z"));
        final Clock clock = clockOf(now);
        final var heartbeats = new AtomicInteger();

        final Runnable deadline = PolicyEvaluationDeadline.wrapping(
                heartbeats::incrementAndGet,
                Duration.ofMinutes(5),
                clock);

        assertThatNoException().isThrownBy(deadline::run);
        assertThat(heartbeats.get()).isEqualTo(1);

        now.set(Instant.parse("2024-01-01T00:04:59Z"));
        assertThatNoException().isThrownBy(deadline::run);
        assertThat(heartbeats.get()).isEqualTo(2);
    }

    @Test
    void throwsAfterDeadlineWithoutInvokingHeartbeat() {
        final var now = new AtomicReference<>(Instant.parse("2024-01-01T00:00:00Z"));
        final Clock clock = clockOf(now);
        final var heartbeats = new AtomicInteger();

        final Runnable deadline = PolicyEvaluationDeadline.wrapping(
                heartbeats::incrementAndGet,
                Duration.ofMinutes(5),
                clock);

        now.set(Instant.parse("2024-01-01T00:05:00.001Z"));

        assertThatExceptionOfType(PolicyEvaluationTimedOutException.class)
                .isThrownBy(deadline::run)
                .extracting(PolicyEvaluationTimedOutException::maxDuration)
                .isEqualTo(Duration.ofMinutes(5));
        assertThat(heartbeats.get()).isZero();
    }

    @Test
    void rejectsNonPositiveMaxDuration() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PolicyEvaluationDeadline.wrapping(() -> {
                }, Duration.ZERO));
    }

    private static Clock clockOf(AtomicReference<Instant> now) {
        return new Clock() {
            @Override
            public ZoneOffset getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Instant instant() {
                return now.get();
            }
        };
    }

}
