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
package org.dependencytrack.vulnanalysis.api;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RetryableVulnAnalysisExceptionTest {

    @ParameterizedTest
    @ValueSource(longs = {-1, 0})
    @SuppressWarnings("ThrowableNotThrown")
    void shouldRejectNonPositiveRetryAfter(long seconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RetryableVulnAnalysisException(
                        null, null, Duration.of(seconds, ChronoUnit.SECONDS)));
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 400, 401, 402, 403, 404})
    void shouldNotThrowForSuccessOrPermanentError(int statusCode) {
        assertThatNoException().isThrownBy(
                () -> RetryableVulnAnalysisException.throwIfRetryableHttpError(
                        responseOf(statusCode, null)));
    }

    @ParameterizedTest
    @ValueSource(ints = {503, 504})
    void shouldThrowWithoutRetryAfterOnServerError(int statusCode) {
        assertThatExceptionOfType(RetryableVulnAnalysisException.class)
                .isThrownBy(() -> RetryableVulnAnalysisException.throwIfRetryableHttpError(
                        responseOf(statusCode, null)))
                .satisfies(e -> assertThat(e.retryAfter()).isNull());
    }

    @Test
    void shouldThrowWithRetryAfterOnTooManyRequests() {
        assertThatExceptionOfType(RetryableVulnAnalysisException.class)
                .isThrownBy(() -> RetryableVulnAnalysisException.throwIfRetryableHttpError(
                        responseOf(429, "30")))
                .satisfies(e -> assertThat(e.retryAfter()).isEqualTo(Duration.ofSeconds(30)));
    }

    @Test
    void shouldThrowForTransientIoException() {
        assertThatExceptionOfType(RetryableVulnAnalysisException.class).isThrownBy(
                () -> RetryableVulnAnalysisException.throwIfRetryableNetworkError(
                        new SocketException("reset"), "boom"));
    }

    @Test
    void shouldNotThrowForPermanentIoException() {
        assertThatNoException().isThrownBy(
                () -> RetryableVulnAnalysisException.throwIfRetryableNetworkError(
                        new SSLHandshakeException("bad cert"), "boom"));
    }

    private static HttpResponse<?> responseOf(int statusCode, @Nullable String retryAfter) {
        final HttpHeaders headers = HttpHeaders.of(
                retryAfter != null
                        ? Map.of("Retry-After", List.of(retryAfter))
                        : Map.of(),
                (_, _) -> true);
        final var request = HttpRequest
                .newBuilder(URI.create("https://example.com"))
                .GET()
                .build();

        return new HttpResponse<>() {
            @Override
            public int statusCode() {
                return statusCode;
            }

            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public Optional<HttpResponse<Object>> previousResponse() {
                return Optional.empty();
            }

            @Override
            public HttpHeaders headers() {
                return headers;
            }

            @Override
            public @Nullable Object body() {
                return null;
            }

            @Override
            public Optional<SSLSession> sslSession() {
                return Optional.empty();
            }

            @Override
            public URI uri() {
                return request.uri();
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
    }

}
