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

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
        final HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(201);

        assertThatCode(() -> HttpNotificationResponses.ensureStatusCode(response, 201, "failed: ", ""))
                .doesNotThrowAnyException();
    }

    @Test
    void ensureStatusCodeShouldThrowForUnexpectedStatus() {
        final HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);

        assertThatThrownBy(() -> HttpNotificationResponses.ensureStatusCode(
                response,
                201,
                "Request failed with retryable response code: ",
                "unexpected response payload"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Request failed with retryable response code: 200");
    }

    @Test
    void ensureSuccessful2xxResponseShouldThrowForUnexpectedStatus() {
        final HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(400);

        assertThatThrownBy(() -> HttpNotificationResponses.ensureSuccessful2xxResponse(response, "bad request"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Request failed with unexpected response code: 400");
    }

}
