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

import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;
import feign.jackson.JacksonEncoder;

import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

public class CompositeEncoder implements Encoder {

    private final Encoder jsonEncoder = new JacksonEncoder();

    @Override
    @SuppressWarnings("unchecked")
    public void encode(final Object object, final Type bodyType, final RequestTemplate template) throws EncodeException {
        if (bodyType == Encoder.MAP_STRING_WILDCARD) {
            final Map<String, ?> body = (Map<String, ?>) object;
            template.body(body.entrySet().stream()
                    .map(entry -> "%s=%s".formatted(
                            URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8),
                            URLEncoder.encode(String.valueOf(entry.getValue()), StandardCharsets.UTF_8)
                    ))
                    .collect(Collectors.joining("&")));
        } else {
            jsonEncoder.encode(object, bodyType, template);
        }
    }

}
