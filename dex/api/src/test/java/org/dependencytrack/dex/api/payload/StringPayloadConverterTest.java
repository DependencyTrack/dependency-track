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
package org.dependencytrack.dex.api.payload;

import com.google.protobuf.ByteString;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class StringPayloadConverterTest {

    private final StringPayloadConverter converter = new StringPayloadConverter();

    @Test
    void convertToPayloadShouldReturnNullWhenArgumentIsNull() {
        assertThat(converter.convertToPayload(null)).isNull();
    }

    @Test
    void convertToPayloadShouldReturnPayloadWithBinaryContent() {
        final Payload payload = converter.convertToPayload("foo");
        assertThat(payload).isNotNull();
        assertThat(payload.hasBinaryContent()).isTrue();

        final Payload.BinaryContent binaryContent = payload.getBinaryContent();
        assertThat(binaryContent.getMediaType()).isEqualTo("text/plain");
        assertThat(binaryContent.getData().toStringUtf8()).isEqualTo("foo");
    }

    @Test
    void convertFromPayloadShouldReturnNullWhenArgumentIsNull() {
        assertThat(converter.convertFromPayload(null)).isNull();
    }

    @Test
    void convertFromPayloadShouldReturnPayloadContent() {
        final var payload = Payload.newBuilder()
                .setBinaryContent(Payload.BinaryContent.newBuilder()
                        .setMediaType("text/plain")
                        .setData(ByteString.copyFromUtf8("foo"))
                        .build())
                .build();

        assertThat(converter.convertFromPayload(payload)).isEqualTo("foo");
    }

    @Test
    void convertFromPayloadShouldThrowWhenNotHavingBinaryContent() {
        final var payload = Payload.getDefaultInstance();

        assertThatExceptionOfType(PayloadConversionException.class)
                .isThrownBy(() -> converter.convertFromPayload(payload))
                .withMessage("Expected payload to have binary content, but was: CONTENT_NOT_SET");
    }

    @Test
    void convertFromPayloadShouldThrowWhenMediaTypeIsNotTextPlain() {
        final var payload = Payload.newBuilder()
                .setBinaryContent(Payload.BinaryContent.newBuilder()
                        .setMediaType("application/json")
                        .setData(ByteString.copyFromUtf8("{\"foo\":\"bar\"}"))
                        .build())
                .build();

        assertThatExceptionOfType(PayloadConversionException.class)
                .isThrownBy(() -> converter.convertFromPayload(payload))
                .withMessage("Expected binary content of type text/plain, but got application/json");
    }

}