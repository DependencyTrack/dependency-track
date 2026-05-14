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
package org.dependencytrack.v4migrator.extract;

import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Persists the operator-supplied metrics retention cutoff into {@code migration_config} so
 * the transform and load phases can read it back. v4 has no equivalent setting; the value
 * must come from {@code --metrics-retention-days} on the {@code extract} / {@code run}
 * command.
 */
final class MetricsRetention {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsRetention.class);

    private MetricsRetention() {
    }

    static void resolveAndPersist(final int days, final GlobalOptions options, final Jdbi target) {
        if (days < 0) {
            throw new IllegalArgumentException(
                "--metrics-retention-days must be >= 0 (0 drops all metrics, N > 0 keeps N days)");
        }
        final Instant cutoff = Instant.now().minus(days, ChronoUnit.DAYS);
        LOGGER.info("Metrics retention set to {} days (cutoff = {})", days, cutoff);
        target.useHandle(h -> {
            h.createUpdate("""
                    INSERT INTO "%s".migration_config (key, value) VALUES (:k, :v)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                    """.formatted(options.stagingSchema))
                .bind("k", "metrics_retention_days")
                .bind("v", Integer.toString(days))
                .execute();
            h.createUpdate("""
                    INSERT INTO "%s".migration_config (key, value) VALUES (:k, :v)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                    """.formatted(options.stagingSchema))
                .bind("k", "metrics_retention_cutoff_at")
                .bind("v", cutoff.toString())
                .execute();
        });
    }
}
