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

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Base64;

/**
 * @since 5.0.0
 */
public final class SimplePageTokenEncoder implements PageTokenEncoder {

    private static final int MAX_ENCODED_LENGTH = 8192;
    private static final ObjectMapper OBJECT_MAPPER = new CBORMapper(
            CBORFactory
                    .builder()
                    .streamReadConstraints(
                            StreamReadConstraints.builder()
                                    .maxStringLength(1024)
                                    .maxNumberLength(20)
                                    .maxNestingDepth(4)
                                    .maxDocumentLength(4096)
                                    .build())
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public SimplePageTokenEncoder() {

    }

    @Override
    public @Nullable String encode(@Nullable PageToken pageToken) {
        if (pageToken == null) {
            return null;
        }

        try {
            final byte[] pageTokenBytes = OBJECT_MAPPER.writeValueAsBytes(pageToken);
            final String encoded = Base64.getUrlEncoder().encodeToString(pageTokenBytes);
            if (encoded.length() > MAX_ENCODED_LENGTH) {
                throw new IllegalStateException(
                        "Encoded token of size %d exceeds maximum size %d".formatted(
                                encoded.length(), MAX_ENCODED_LENGTH));
            }
            return encoded;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public <T extends PageToken> @Nullable T decode(@Nullable String encoded, Class<T> pageTokenClass) {
        if (encoded == null) {
            return null;
        }
        if (encoded.length() > MAX_ENCODED_LENGTH) {
            throw new InvalidPageTokenException(
                    "Token of size %d exceeds maximum size %d".formatted(
                            encoded.length(), MAX_ENCODED_LENGTH));
        }

        try {
            final byte[] pageTokenBytes = Base64.getUrlDecoder().decode(encoded);
            return OBJECT_MAPPER.readValue(pageTokenBytes, pageTokenClass);
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
