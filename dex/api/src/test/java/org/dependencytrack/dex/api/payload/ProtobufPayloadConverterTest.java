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

import com.google.protobuf.Any;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ProtobufPayloadConverterTest {

    @Test
    void convertToPayloadShouldReturnNullWhenArgumentIsNull() {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        assertThat(converter.convertToPayload(null)).isNull();
    }

    @Test
    void convertToPayloadShouldReturnPayloadWithProtoContent() throws Exception {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        final var event = WorkflowEvent.getDefaultInstance();

        final Payload payload = converter.convertToPayload(event);
        assertThat(payload).isNotNull();
        assertThat(payload.hasProtoContent()).isTrue();

        final Any protoContent = payload.getProtoContent();
        assertThat(protoContent.is(WorkflowEvent.class)).isTrue();
        assertThat(protoContent.unpack(WorkflowEvent.class)).isEqualTo(event);
    }

    @Test
    void convertFromPayloadShouldReturnNullWhenArgumentIsNull() {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        assertThat(converter.convertFromPayload(null)).isNull();
    }

    @Test
    void convertFromPayloadShouldReturnProtobufContent() {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        final var event = WorkflowEvent.getDefaultInstance();
        final var payload = Payload.newBuilder()
                .setProtoContent(Any.pack(event))
                .build();

        assertThat(converter.convertFromPayload(payload)).isEqualTo(event);
    }

    @Test
    void convertFromPayloadShouldThrowWhenNotHavingProtobufContent() {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        final var payload = Payload.getDefaultInstance();

        assertThatExceptionOfType(PayloadConversionException.class)
                .isThrownBy(() -> converter.convertFromPayload(payload))
                .withMessage("Expected payload to have protobuf content, but was: CONTENT_NOT_SET");
    }

    @Test
    void convertFromPayloadShouldThrowOnProtobufTypeMismatch() {
        final var converter = new ProtobufPayloadConverter<>(WorkflowEvent.class);
        final var payload = Payload.newBuilder()
                .setProtoContent(Any.pack(Failure.getDefaultInstance()))
                .build();

        assertThatExceptionOfType(PayloadConversionException.class)
                .isThrownBy(() -> converter.convertFromPayload(payload))
                .withMessage("""
                        Expected Protobuf payload to be of type org.dependencytrack.dex.proto.event.v1.WorkflowEvent, \
                        but was type.googleapis.com/org.dependencytrack.dex.failure.v1.Failure""");
    }

}