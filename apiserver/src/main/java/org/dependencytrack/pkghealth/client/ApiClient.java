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
package org.dependencytrack.pkghealth.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.common.Mappers;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

@NullMarked
abstract class ApiClient {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration DEFAULT_RATE_LIMIT_WAIT = Duration.ofMinutes(1);

    protected final java.net.http.HttpClient httpClient;
    protected final ObjectMapper objectMapper;

    protected ApiClient() {
        this(HttpClient.INSTANCE, Mappers.jsonMapper());
    }

    protected ApiClient(java.net.http.HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.objectMapper = requireNonNull(objectMapper, "objectMapper must not be null");
    }

    protected final HttpResponse<String> get(String url) throws IOException, InterruptedException {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json")
                .GET();

        configureRequest(requestBuilder);

        return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    protected final Optional<JsonNode> requestJson(String url) throws IOException, InterruptedException {
        final HttpResponse<String> response = get(url);

        if (response.statusCode() == 404 || response.statusCode() == 204) {
            return Optional.empty();
        }

        final Instant rateLimitResetAt = rateLimitResetAt(response);
        if (rateLimitResetAt != null) {
            throw new ApiRateLimitException(rateLimitResetAt);
        }

        if (response.statusCode() != 200) {
            final var headers = response.headers();
            throw new IOException("API returned HTTP %d for %s (limit=%s, used=%s, remaining=%s, reset=%s, resource=%s)"
                    .formatted(
                            response.statusCode(),
                            url,
                            headers.firstValue("x-ratelimit-limit").orElse("unknown"),
                            headers.firstValue("x-ratelimit-used").orElse("unknown"),
                            headers.firstValue("x-ratelimit-remaining").orElse("unknown"),
                            headers.firstValue("x-ratelimit-reset").orElse("unknown"),
                            headers.firstValue("x-ratelimit-resource").orElse("unknown")));
        }

        return Optional.of(objectMapper.readTree(response.body()));
    }

    /**
     * Follows GitHub's guidance for primary and secondary rate limits, which also covers deps.dev:
     * honor {@code retry-after}, then {@code x-ratelimit-reset} when no requests remain, and
     * otherwise wait one minute after a 429.
     *
     * @see <a href="https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#handle-rate-limit-errors-appropriately">GitHub rate limit handling</a>
     */
    private static @Nullable Instant rateLimitResetAt(final HttpResponse<?> response) {
        final int status = response.statusCode();
        if (status != 403 && status != 429) {
            return null;
        }

        final HttpHeaders headers = response.headers();
        final Long retryAfterSeconds = parseLong(headers.firstValue("retry-after"));
        if (retryAfterSeconds != null) {
            return Instant.now().plusSeconds(retryAfterSeconds);
        }

        if (headers.firstValue("x-ratelimit-remaining").filter("0"::equals).isPresent()) {
            final Long resetEpochSeconds = parseLong(headers.firstValue("x-ratelimit-reset"));
            if (resetEpochSeconds != null) {
                return Instant.ofEpochSecond(resetEpochSeconds);
            }
        }

        return status == 429 ? Instant.now().plus(DEFAULT_RATE_LIMIT_WAIT) : null;
    }

    private static @Nullable Long parseLong(final Optional<String> value) {
        try {
            return value.isPresent() ? Long.parseLong(value.get().trim()) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    protected final <T> Optional<T> requestParseJsonForResult(String url, Function<JsonNode, Optional<T>> parser)
            throws IOException, InterruptedException {
        requireNonNull(parser, "parser must not be null");

        final Optional<JsonNode> response = requestJson(url);
        if (response.isEmpty()) {
            return Optional.empty();
        }

        try {
            return requireNonNull(parser.apply(response.get()), "parser result must not be null");
        } catch (RuntimeException e) {
            throw new IOException("Failed to parse API response from " + url, e);
        }
    }

    protected void configureRequest(HttpRequest.Builder requestBuilder) {
        // Subclasses may add headers, for example GitHub authentication.
    }

    protected static String urlEncode(String value) {
        requireNonNull(value, "value must not be null");

        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
