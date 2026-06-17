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
import org.jspecify.annotations.Nullable;

final class StringPayloadConverter implements PayloadConverter<String> {

    private static final String MEDIA_TYPE = "text/plain";
    static final StringPayloadConverter INSTANCE = new StringPayloadConverter();

    @Override
    public @Nullable Payload convertToPayload(final @Nullable String value) {
        if (value == null) {
            return null;
        }

        return Payload.newBuilder()
                .setBinaryContent(Payload.BinaryContent.newBuilder()
                        .setMediaType(MEDIA_TYPE)
                        .setData(ByteString.copyFromUtf8(value))
                        .build())
                .build();
    }

    @Override
    public @Nullable String convertFromPayload(final @Nullable Payload payload) {
        if (payload == null) {
            return null;
        }

        if (!payload.hasBinaryContent()) {
            throw new PayloadConversionException(
                    "Expected payload to have binary content, but was: " + payload.getContentCase());
        }

        final Payload.BinaryContent binaryContent = payload.getBinaryContent();
        if (!MEDIA_TYPE.equals(binaryContent.getMediaType())) {
            throw new PayloadConversionException(
                    "Expected binary content of type %s, but got %s".formatted(
                            MEDIA_TYPE, binaryContent.getMediaType()));
        }

        return payload.getBinaryContent().getData().toStringUtf8();
    }

}
