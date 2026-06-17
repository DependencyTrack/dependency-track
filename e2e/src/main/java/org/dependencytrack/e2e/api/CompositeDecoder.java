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
package org.dependencytrack.e2e.api;

import feign.FeignException;
import feign.Response;
import feign.codec.Decoder;
import feign.jackson.JacksonDecoder;

import java.io.BufferedReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.stream.Collectors;

public class CompositeDecoder implements Decoder {

    private final Decoder jsonDecoder = new JacksonDecoder();

    @Override
    public Object decode(final Response response, final Type type) throws IOException, FeignException {
        final String contentType = response.headers().getOrDefault("Content-Type", Collections.emptyList()).stream()
                .findFirst()
                .orElse(null);

        if (contentType != null && contentType.startsWith("application/json")) {
            return jsonDecoder.decode(response, type);
        }

        try (final var reader = new BufferedReader(response.body().asReader(StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining());
        }
    }

}
