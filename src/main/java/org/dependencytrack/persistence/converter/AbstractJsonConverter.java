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
package org.dependencytrack.persistence.converter;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.jdo.AttributeConverter;

/**
 * @since 4.10.0
 */
abstract class AbstractJsonConverter<T> implements AttributeConverter<T, String> {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final TypeReference<T> typeReference;

    AbstractJsonConverter(final TypeReference<T> typeReference) {
        this.typeReference = typeReference;
    }

    @Override
    public String convertToDatastore(final T attributeValue) {
        if (attributeValue == null) {
            return null;
        }

        try {
            return OBJECT_MAPPER.writeValueAsString(attributeValue);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public T convertToAttribute(final String datastoreValue) {
        if (datastoreValue == null) {
            return null;
        }

        try {
            return OBJECT_MAPPER.readValue(datastoreValue, typeReference);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }

}
