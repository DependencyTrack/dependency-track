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
package org.dependencytrack.common.pagination;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SimplePageTokenEncoderTest {

    private final SimplePageTokenEncoder encoder = new SimplePageTokenEncoder();

    public static class TestPageToken implements PageToken {

        public int offset;
        public String value;

    }

    @Test
    void encodeShouldReturnNullWhenTokenIsNull() {
        assertThat(encoder.encode(null)).isNull();
    }

    @Test
    void decodeShouldReturnNullWhenEncodedIsNull() {
        assertThat(encoder.decode(null, TestPageToken.class)).isNull();
    }

    @Test
    void shouldRoundTrip() {
        final var token = new TestPageToken();
        token.offset = 666;

        final String encoded = encoder.encode(token);
        assertThat(encoded).isNotNull().isNotBlank();

        final TestPageToken decoded = encoder.decode(encoded, TestPageToken.class);
        assertThat(decoded).isNotNull();
        assertThat(decoded.offset).isEqualTo(666);
    }

    @Test
    void decodeShouldThrowForInvalidBase64() {
        assertThatExceptionOfType(InvalidPageTokenException.class)
                .isThrownBy(() -> encoder.decode("invalid-base64", TestPageToken.class));
    }

    @Test
    void decodeShouldThrowForMalformedJson() {
        final String encoded = Base64.getUrlEncoder()
                .encodeToString("{invalid".getBytes(StandardCharsets.UTF_8));

        assertThatExceptionOfType(InvalidPageTokenException.class)
                .isThrownBy(() -> encoder.decode(encoded, TestPageToken.class));
    }

    @Test
    void encodeShouldThrowWhenEncodedExceedsMaximumLength() {
        final var token = new TestPageToken();
        token.value = "A".repeat(7000);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> encoder.encode(token))
                .withMessageContaining("exceeds maximum size");
    }

    @Test
    void decodeShouldThrowWhenEncodedExceedsMaximumLength() {
        final String encoded = "A".repeat(8193);

        assertThatExceptionOfType(InvalidPageTokenException.class)
                .isThrownBy(() -> encoder.decode(encoded, TestPageToken.class))
                .withMessageContaining("exceeds maximum size");
    }

}