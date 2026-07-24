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
package org.dependencytrack.notification.publishing.http;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpNotificationResponsesTest {

    @Test
    void truncateShouldReturnEmptyStringForNullOrBlankValues() {
        assertThat(HttpNotificationResponses.truncate(null, 10)).isEmpty();
        assertThat(HttpNotificationResponses.truncate("", 10)).isEmpty();
    }

    @Test
    void truncateShouldReturnOriginalValueWhenWithinLimit() {
        assertThat(HttpNotificationResponses.truncate("short body", 100)).isEqualTo("short body");
    }

    @Test
    void truncateShouldLimitValueToMaxLength() {
        final var value = "a".repeat(150);

        assertThat(HttpNotificationResponses.truncate(value, 100))
                .hasSize(100)
                .isEqualTo("a".repeat(100));
    }

    @Test
    void ensureStatusCodeShouldNotThrowForExpectedStatus() {
        assertThatCode(() -> HttpNotificationResponses.ensureStatusCode(
                stubResponse(201),
                201,
                "failed: ",
                ""))
                .doesNotThrowAnyException();
    }

    @Test
    void ensureStatusCodeShouldThrowForUnexpectedStatus() {
        assertThatThrownBy(() -> HttpNotificationResponses.ensureStatusCode(
                stubResponse(200),
                201,
                "Request failed with retryable response code: ",
                "unexpected response payload"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Request failed with retryable response code: 200");
    }

    @Test
    void ensureSuccessful2xxResponseShouldThrowForUnexpectedStatus() {
        assertThatThrownBy(() -> HttpNotificationResponses.ensureSuccessful2xxResponse(
                stubResponse(400),
                "bad request"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Request failed with unexpected response code: 400");
    }

    private static HttpResponse<Object> stubResponse(final int statusCode) {
        final var request = HttpRequest.newBuilder(URI.create("http://localhost")).GET().build();
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
                return HttpHeaders.of(Map.of(), (name, value) -> true);
            }

            @Override
            public Object body() {
                return null;
            }

            @Override
            public Optional<javax.net.ssl.SSLSession> sslSession() {
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
