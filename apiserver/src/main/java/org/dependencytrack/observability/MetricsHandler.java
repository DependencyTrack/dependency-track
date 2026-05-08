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
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class MetricsHandler implements HttpHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsHandler.class);

    private final PrometheusMeterRegistry meterRegistry;
    private final @Nullable String basicAuthUsername;
    private final @Nullable String basicAuthPassword;

    MetricsHandler(
            PrometheusMeterRegistry meterRegistry,
            @Nullable String basicAuthUsername,
            @Nullable String basicAuthPassword) {
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.basicAuthUsername = basicAuthUsername;
        this.basicAuthPassword = basicAuthPassword;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (isAuthenticationEnabled() && !isAuthenticated(exchange)) {
                final String remoteAddress = exchange.getRemoteAddress().getAddress().getHostAddress();
                final String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
                LOGGER.warn(
                        SecurityMarkers.SECURITY_AUDIT,
                        "Unauthorized access attempt (IP address: {} / User-Agent: {})",
                        remoteAddress, userAgent);
                exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"metrics\"");
                exchange.sendResponseHeaders(401, -1);
                return;
            }

            exchange.getResponseHeaders().set("Content-Type", TextFormat.CONTENT_TYPE_004);
            exchange.sendResponseHeaders(200, 0);
            meterRegistry.scrape(exchange.getResponseBody());
        }
    }

    private boolean isAuthenticationEnabled() {
        return StringUtils.isNotBlank(basicAuthUsername) && StringUtils.isNotBlank(basicAuthPassword);
    }

    private boolean isAuthenticated(HttpExchange exchange) {
        final String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (StringUtils.isBlank(authHeader)) {
            return false;
        }

        final String[] headerParts = authHeader.split("\\s");
        if (headerParts.length != 2 || !"basic".equalsIgnoreCase(headerParts[0])) {
            return false;
        }

        final String credentials;
        try {
            final byte[] credentialsBytes = Base64.getDecoder().decode(headerParts[1]);
            credentials = new String(credentialsBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return false;
        }

        final String[] credentialsParts = credentials.split(":", 2);
        if (credentialsParts.length != 2) {
            return false;
        }

        return Objects.equals(basicAuthUsername, credentialsParts[0])
                && Objects.equals(basicAuthPassword, credentialsParts[1]);
    }

}
