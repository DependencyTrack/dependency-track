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
package org.dependencytrack.observability;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.common.health.HealthCheckType;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.eclipse.microprofile.health.Readiness;
import org.eclipse.microprofile.health.Startup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;

/**
 * @since 5.0.0
 */
final class HealthHandler implements HttpHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(HealthHandler.class);

    private final HealthCheckRegistry healthCheckRegistry;

    HealthHandler(HealthCheckRegistry healthCheckRegistry) {
        this.healthCheckRegistry = healthCheckRegistry;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            final String path = exchange.getRequestURI().getPath();
            final HealthCheckType checkType = determineHealthCheckType(path);

            final var checkResponses = new ArrayList<HealthCheckResponse>();
            try {
                for (final HealthCheck healthCheck : healthCheckRegistry.getChecks()) {
                    if (matchesCheckType(healthCheck, checkType)) {
                        checkResponses.add(healthCheck.call());
                    }
                }
            } catch (Exception e) {
                LOGGER.error("Failed to execute health checks", e);
                exchange.sendResponseHeaders(500, -1);
                return;
            }

            final HealthCheckResponse.Status overallStatus = checkResponses.stream()
                    .map(HealthCheckResponse::getStatus)
                    .filter(HealthCheckResponse.Status.DOWN::equals)
                    .findFirst()
                    .orElse(HealthCheckResponse.Status.UP);

            final var responseJson = Mappers.jsonMapper().createObjectNode()
                    .put("status", overallStatus.name())
                    .putPOJO("checks", checkResponses);

            final int statusCode = overallStatus == HealthCheckResponse.Status.UP ? 200 : 503;
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, 0);
            Mappers.jsonMapper().writeValue(exchange.getResponseBody(), responseJson);
        }
    }

    private static HealthCheckType determineHealthCheckType(String path) {
        return switch (path) {
            case "/health/live" -> HealthCheckType.LIVENESS;
            case "/health/ready" -> HealthCheckType.READINESS;
            case "/health/started" -> HealthCheckType.STARTUP;
            default -> HealthCheckType.ALL;
        };
    }

    private static boolean matchesCheckType(HealthCheck check, HealthCheckType requestedType) {
        final Class<? extends HealthCheck> checkClass = check.getClass();
        if (checkClass.isAnnotationPresent(Liveness.class)
                && (requestedType == HealthCheckType.ALL || requestedType == HealthCheckType.LIVENESS)) {
            return true;
        } else if (checkClass.isAnnotationPresent(Readiness.class)
                && (requestedType == HealthCheckType.ALL || requestedType == HealthCheckType.READINESS)) {
            return true;
        }

        return checkClass.isAnnotationPresent(Startup.class)
                && (requestedType == HealthCheckType.ALL || requestedType == HealthCheckType.STARTUP);
    }

}
