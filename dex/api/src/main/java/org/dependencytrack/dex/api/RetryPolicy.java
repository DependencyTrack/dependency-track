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

import com.google.protobuf.util.Durations;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

public record RetryPolicy(
        Duration initialDelay,
        double delayMultiplier,
        double delayRandomizationFactor,
        Duration maxDelay,
        int maxAttempts) {

    public RetryPolicy {
        requireNonNull(initialDelay, "initialDelay must not be null");
        if (initialDelay.isZero() || initialDelay.isNegative()) {
            throw new IllegalArgumentException("initialDelay must be positive");
        }
        if (delayMultiplier <= 0) {
            throw new IllegalArgumentException("delayMultiplier must be positive");
        }
        if (delayRandomizationFactor <= 0) {
            throw new IllegalArgumentException("delayRandomizationFactor must be positive");
        }
        requireNonNull(maxDelay, "maxDelay must not be null");
        if (maxDelay.isZero() || maxDelay.isNegative()) {
            throw new IllegalArgumentException("maxDelay must be positive");
        }
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be positive");
        }
    }

    public static RetryPolicy ofDefault() {
        return new RetryPolicy(Duration.ofSeconds(5), 1.5, 0.3, Duration.ofMinutes(30), 6);
    }

    public static RetryPolicy fromProto(final org.dependencytrack.dex.proto.common.v1.RetryPolicy protoPolicy) {
        return new RetryPolicy(
                Duration.ofMillis(Durations.toMillis(protoPolicy.getInitialDelay())),
                protoPolicy.getDelayMultiplier(),
                protoPolicy.getDelayRandomizationFactor(),
                Duration.ofMillis(Durations.toMillis(protoPolicy.getMaxDelay())),
                protoPolicy.getMaxAttempts());
    }

    public org.dependencytrack.dex.proto.common.v1.RetryPolicy toProto() {
        return org.dependencytrack.dex.proto.common.v1.RetryPolicy.newBuilder()
                .setInitialDelay(Durations.fromMillis(this.initialDelay.toMillis()))
                .setDelayMultiplier((float) this.delayMultiplier)
                .setDelayRandomizationFactor((float) this.delayRandomizationFactor)
                .setMaxDelay(Durations.fromMillis(this.maxDelay.toMillis()))
                .setMaxAttempts(this.maxAttempts)
                .build();
    }

    public RetryPolicy withInitialDelay(final Duration initialDelay) {
        return new RetryPolicy(
                initialDelay,
                this.delayMultiplier,
                this.delayRandomizationFactor,
                this.maxDelay,
                this.maxAttempts);
    }

    public RetryPolicy withDelayMultiplier(final double delayMultiplier) {
        return new RetryPolicy(
                this.initialDelay,
                delayMultiplier,
                this.delayRandomizationFactor,
                this.maxDelay,
                this.maxAttempts);
    }

    public RetryPolicy withDelayRandomizationFactor(final double delayRandomizationFactor) {
        return new RetryPolicy(
                this.initialDelay,
                this.delayMultiplier,
                delayRandomizationFactor,
                this.maxDelay,
                this.maxAttempts);
    }

    public RetryPolicy withMaxDelay(final Duration maxDelay) {
        return new RetryPolicy(
                this.initialDelay,
                this.delayMultiplier,
                this.delayRandomizationFactor,
                maxDelay,
                this.maxAttempts);
    }

    public RetryPolicy withMaxAttempts(final int maxAttempts) {
        return new RetryPolicy(
                this.initialDelay,
                this.delayMultiplier,
                this.delayRandomizationFactor,
                this.maxDelay,
                maxAttempts);
    }

}
