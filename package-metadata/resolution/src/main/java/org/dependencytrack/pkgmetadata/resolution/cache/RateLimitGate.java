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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 5.0.0
 */
final class RateLimitGate {

    private static final Duration DEFAULT_BACKOFF = Duration.ofSeconds(30);
    private static final Duration MAX_BACKOFF = Duration.ofMinutes(5);

    private final Map<String, Instant> rateLimitedUntilByHost = new ConcurrentHashMap<>();
    private final Clock clock;

    RateLimitGate(Clock clock) {
        this.clock = clock;
    }

    @Nullable Instant checkRateLimited(URI uri) {
        final String key = uri.getAuthority();
        if (key == null) {
            return null;
        }

        return rateLimitedUntilByHost
                .computeIfPresent(
                        key,
                        (k, until) -> clock.instant().isBefore(until) ? until : null);
    }

    Duration recordRateLimit(URI uri, @Nullable Duration retryAfter) {
        Duration backoffDuration = retryAfter != null
                ? retryAfter
                : DEFAULT_BACKOFF;
        backoffDuration = backoffDuration.compareTo(MAX_BACKOFF) > 0
                ? MAX_BACKOFF
                : backoffDuration;

        final String hostKey = uri.getAuthority();
        if (hostKey == null) {
            return backoffDuration;
        }

        final Instant now = clock.instant();
        final Instant proposedUntil = now.plus(backoffDuration);
        final Instant effectiveUntil = rateLimitedUntilByHost.merge(
                hostKey,
                proposedUntil,
                (existing, proposed) -> proposed.isAfter(existing) ? proposed : existing);
        
        final Duration effective = Duration.between(now, effectiveUntil);
        return effective.isPositive() ? effective : backoffDuration;
    }

}
