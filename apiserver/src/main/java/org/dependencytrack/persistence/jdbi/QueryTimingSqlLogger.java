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
package org.dependencytrack.persistence.jdbi;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.jdbi.v3.core.extension.ExtensionMethod;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.StatementContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;

/**
 * @since 5.0.0
 */
final class QueryTimingSqlLogger implements SqlLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(QueryTimingSqlLogger.class);

    private final MeterRegistry meterRegistry;

    QueryTimingSqlLogger(final MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void logException(final StatementContext context, final SQLException ex) {
        recordQueryLatency(context, ex);
    }

    @Override
    public void logAfterExecution(final StatementContext context) {
        recordQueryLatency(context, null);
    }

    private void recordQueryLatency(final StatementContext context, final SQLException ex) {
        if (meterRegistry == null) {
            return;
        }

        final String queryName = getQueryName(context);
        if (queryName == null) {
            return;
        }

        final long latencyNanos = context.getElapsedTime(ChronoUnit.NANOS);
        final String outcome = ex == null ? "success" : "failure";

        Timer.builder("jdbi.query.latency")
                .tag("query", queryName)
                .tag("outcome", outcome)
                .register(meterRegistry)
                .record(latencyNanos, TimeUnit.NANOSECONDS);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Query {} completed with outcome {} in {}", queryName, outcome, Duration.ofNanos(latencyNanos));
        }
    }

    private String getQueryName(final StatementContext context) {
        if (context.getAttribute(ATTRIBUTE_QUERY_NAME) instanceof final String queryNameAttribute) {
            return queryNameAttribute;
        }

        final ExtensionMethod extensionMethod = context.getExtensionMethod();
        if (extensionMethod != null) {
            return "%s#%s".formatted(
                    extensionMethod.getType().getSimpleName(),
                    extensionMethod.getMethod().getName());
        }

        return null;
    }

}
