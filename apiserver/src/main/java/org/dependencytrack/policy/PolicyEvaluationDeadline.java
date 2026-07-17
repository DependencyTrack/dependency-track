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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Wraps a heartbeat callback with a wall-clock deadline for policy evaluation.
 * <p>
 * Once the deadline has passed, {@link #run()} throws
 * {@link PolicyEvaluationTimedOutException} and does not invoke the heartbeat.
 *
 * @since 5.0.0
 */
public final class PolicyEvaluationDeadline implements Runnable {

    private final Runnable heartbeat;
    private final Duration maxDuration;
    private final Instant deadline;
    private final Clock clock;

    private PolicyEvaluationDeadline(
            Runnable heartbeat,
            Duration maxDuration,
            Instant deadline,
            Clock clock) {
        this.heartbeat = heartbeat;
        this.maxDuration = maxDuration;
        this.deadline = deadline;
        this.clock = clock;
    }

    public static Runnable wrapping(Runnable heartbeat, Duration maxDuration) {
        return wrapping(heartbeat, maxDuration, Clock.systemUTC());
    }

    static Runnable wrapping(Runnable heartbeat, Duration maxDuration, Clock clock) {
        requireNonNull(heartbeat, "heartbeat must not be null");
        requireNonNull(maxDuration, "maxDuration must not be null");
        requireNonNull(clock, "clock must not be null");
        if (!maxDuration.isPositive()) {
            throw new IllegalArgumentException("maxDuration must be positive");
        }

        return new PolicyEvaluationDeadline(
                heartbeat,
                maxDuration,
                clock.instant().plus(maxDuration),
                clock);
    }

    @Override
    public void run() {
        if (clock.instant().isAfter(deadline)) {
            throw new PolicyEvaluationTimedOutException(maxDuration);
        }
        heartbeat.run();
    }

}
