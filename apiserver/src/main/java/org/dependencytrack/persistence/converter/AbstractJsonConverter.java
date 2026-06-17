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
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import javax.jdo.AttributeConverter;
import java.io.IOException;

/**
 * @since 4.10.0
 */
abstract class AbstractJsonConverter<T> implements AttributeConverter<T, String> {

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder()
            .disable(MapperFeature.DEFAULT_VIEW_INCLUSION)
            .build();

    private final TypeReference<T> typeReference;
    private final Class<?> jsonView;

    AbstractJsonConverter(final TypeReference<T> typeReference) {
        this(typeReference, null);
    }

    AbstractJsonConverter(final TypeReference<T> typeReference, final Class<?> jsonView) {
        this.typeReference = typeReference;
        this.jsonView = jsonView;
    }

    @Override
    public String convertToDatastore(final T attributeValue) {
        if (attributeValue == null) {
            return null;
        }

        final ObjectWriter objectWriter;
        if (jsonView == null) {
            objectWriter = JSON_MAPPER.writer();
        } else {
            objectWriter = JSON_MAPPER.writerWithView(jsonView);
        }

        try {
            return objectWriter.writeValueAsString(attributeValue);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public T convertToAttribute(final String datastoreValue) {
        if (datastoreValue == null) {
            return null;
        }

        final ObjectReader objectReader;
        if (jsonView == null) {
            objectReader = JSON_MAPPER.reader();
        } else {
            objectReader = JSON_MAPPER.readerWithView(jsonView);
        }

        try {
            final JsonParser jsonParser = objectReader.createParser(datastoreValue);
            return objectReader.readValue(jsonParser, typeReference);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}