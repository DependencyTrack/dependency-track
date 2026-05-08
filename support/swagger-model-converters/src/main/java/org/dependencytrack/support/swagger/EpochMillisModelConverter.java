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
package org.dependencytrack.support.swagger;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.media.Schema;
import org.jspecify.annotations.Nullable;

import java.lang.annotation.Annotation;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Iterator;

/**
 * Maps {@link Date}, {@link Instant}, {@link OffsetDateTime}, and {@link ZonedDateTime}
 * types to {@code integer($int64)} in the generated OpenAPI spec,
 * reflecting that Jackson serializes them as UNIX epoch milliseconds at
 * runtime by default.
 * <p>
 * Conversion is skipped when the field carries a Jackson annotation that
 * overrides the default serialization (e.g. {@code @JsonSerialize} or
 * {@code @JsonFormat}).
 */
@SuppressWarnings("unused") // Invoked by Swagger Maven plugin.
public final class EpochMillisModelConverter implements ModelConverter {

    @Override
    public @Nullable Schema<?> resolve(
            AnnotatedType type,
            ModelConverterContext context,
            Iterator<ModelConverter> chain) {
        final Schema<?> resolved = chain.hasNext()
                ? chain.next().resolve(type, context, chain)
                : null;
        if (resolved == null || type == null || type.getType() == null) {
            return resolved;
        }

        final JavaType javaType = Json.mapper().constructType(type.getType());
        if (javaType == null
                || !isTimestamp(javaType.getRawClass())
                || hasSerializationOverride(type.getCtxAnnotations())) {
            return resolved;
        }

        // Mutate the schema produced by the default resolver so that metadata
        // contributed by @Schema (description, accessMode, example, nullable, ...)
        // is preserved. Clear string-specific facets that don't apply to integers.
        resolved.setType("integer");
        resolved.setFormat("int64");
        resolved.setPattern(null);
        resolved.setMinLength(null);
        resolved.setMaxLength(null);
        if (resolved.getDescription() == null || resolved.getDescription().isBlank()) {
            resolved.setDescription("UNIX epoch timestamp in milliseconds");
        }

        return resolved;
    }

    private static boolean isTimestamp(Class<?> rawClass) {
        return Date.class.isAssignableFrom(rawClass)
                || Instant.class.isAssignableFrom(rawClass)
                || OffsetDateTime.class.isAssignableFrom(rawClass)
                || ZonedDateTime.class.isAssignableFrom(rawClass);
    }

    private static boolean hasSerializationOverride(Annotation @Nullable [] annotations) {
        if (annotations == null) {
            return false;
        }

        for (final Annotation annotation : annotations) {
            if (annotation instanceof JsonSerialize) {
                return true;
            }

            if (annotation instanceof JsonFormat jsonFormat
                    && jsonFormat.shape() == JsonFormat.Shape.STRING) {
                return true;
            }
        }

        return false;
    }

}
