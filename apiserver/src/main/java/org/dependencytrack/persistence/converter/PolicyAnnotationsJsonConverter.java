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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.model.AppliedPolicyAnnotation;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;

public class PolicyAnnotationsJsonConverter extends AbstractJsonConverter<List<AppliedPolicyAnnotation>> {

    private static final TypeReference<List<AppliedPolicyAnnotation>> TYPE_REF = new TypeReference<>() {};

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder()
            .disable(MapperFeature.DEFAULT_VIEW_INCLUSION)
            .addModule(new JavaTimeModule())
            .build();

    public PolicyAnnotationsJsonConverter() {
        super(TYPE_REF);
    }

    public static @Nullable String toJson(@Nullable List<AppliedPolicyAnnotation> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return null;
        }

        try {
            return JSON_MAPPER.writeValueAsString(annotations);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("Failed to serialize policy annotations", e);
        }
    }

    public static @Nullable List<AppliedPolicyAnnotation> fromJson(@Nullable String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        try {
            final JsonNode root = JSON_MAPPER.readTree(json);
            if (!root.isArray()) {
                return JSON_MAPPER.readValue(json, TYPE_REF);
            }

            final var annotations = new ArrayList<AppliedPolicyAnnotation>();
            for (final JsonNode node : root) {
                final AppliedPolicyAnnotation annotation = parseAnnotationNode(node);
                if (annotation != null) {
                    annotations.add(annotation);
                }
            }
            return annotations.isEmpty() ? null : List.copyOf(annotations);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to deserialize policy annotations", e);
        }
    }

    private static @Nullable AppliedPolicyAnnotation parseAnnotationNode(final JsonNode node) {
        String policyName = textOrNull(node, "policyName");
        if (isBlank(policyName)) {
            policyName = textOrNull(node, "value");
        }
        if (isBlank(policyName)) {
            return null;
        }

        Instant appliedAt = null;
        if (node.hasNonNull("appliedAt")) {
            try {
                appliedAt = JSON_MAPPER.treeToValue(node.get("appliedAt"), Instant.class);
            } catch (JacksonException ignored) {
                // Fall through with null appliedAt.
            }
        }

        return new AppliedPolicyAnnotation(policyName, appliedAt, textOrNull(node, "annotator"));
    }

    private static @Nullable String textOrNull(final JsonNode node, final String field) {
        if (!node.hasNonNull(field)) {
            return null;
        }
        final String value = node.get(field).asText();
        return isBlank(value) ? null : value;
    }

    @Override
    public String convertToDatastore(final List<AppliedPolicyAnnotation> attributeValue) {
        return toJson(attributeValue);
    }

    @Override
    public List<AppliedPolicyAnnotation> convertToAttribute(final String datastoreValue) {
        return fromJson(datastoreValue);
    }

}
