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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.client.methods.CloseableHttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.function.Function;

/**
 * Helper class wrapping a Jackson {@link ObjectMapper} and providing various utility methods.
 * <p>
 * The methods in this class are intended to behave similar or exactly the same as those provided
 * by JSON-java, because JSON-java was used throughout the codebase prior to 4.9.0.
 *
 * @see <a href="JSON-java">https://stleary.github.io/JSON-java/index.html</a>
 * @since 4.9.0
 */
public final class Json {

    private static final ObjectMapper OBJECT_MAPPER;

    static {
        OBJECT_MAPPER = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                // Configure time zone and date format to match DateUtil#toISO8601(Date)
                .setTimeZone(TimeZone.getTimeZone("UTC"))
                .setDateFormat(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    }

    private Json() {
    }

    public static ObjectReader objectReader() {
        return OBJECT_MAPPER.reader();
    }

    public static ObjectWriter objectWriter() {
        return OBJECT_MAPPER.writer();
    }

    public static JsonNodeFactory nodeFactory() {
        return OBJECT_MAPPER.getNodeFactory();
    }

    public static ArrayNode newArray() {
        return nodeFactory().arrayNode();
    }

    public static ObjectNode newObject() {
        return nodeFactory().objectNode();
    }

    public static JsonNode readString(final String string) {
        return readString(string, JsonNode.class);
    }

    public static <T> T readString(final String string, Class<T> clazz) {
        try {
            return objectReader().readValue(string, clazz);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static JsonNode readHttpResponse(final CloseableHttpResponse response) throws IOException {
        return readHttpResponse(response, JsonNode.class);
    }

    public static <T> T readHttpResponse(final CloseableHttpResponse response, final Class<T> clazz) throws IOException {
        if (response != null && response.getEntity().getContent() != null) {
            try (final InputStream entityInputStream = response.getEntity().getContent()) {
                return objectReader().readValue(entityInputStream, clazz);
            }
        }
        return null;
    }

    public static String optString(final JsonNode jsonNode, final String fieldName) {
        return optString(jsonNode, fieldName, "");
    }

    public static String optString(final JsonNode jsonNode, final String fieldName, final String fallback) {
        return optField(jsonNode, fieldName, JsonNode::asText, fallback);
    }

    public static String optString(final JsonNode jsonNode, final int index) {
        return optString(jsonNode, index, "");
    }

    public static String optString(final JsonNode jsonNode, final int index, final String fallback) {
        return optField(jsonNode, index, JsonNode::asText, fallback);
    }

    public static int optInt(final JsonNode jsonNode, final String fieldName) {
        return optField(jsonNode, fieldName, JsonNode::asInt, 0);
    }

    public static double optDouble(final JsonNode jsonNode, final String fieldName) {
        return optField(jsonNode, fieldName, JsonNode::asDouble, Double.NaN);
    }

    public static BigDecimal optBigDecimal(final JsonNode jsonNode, final String fieldName) {
        return optField(jsonNode, fieldName, JsonNode::decimalValue, BigDecimal.ZERO);
    }

    public static boolean optBoolean(final JsonNode jsonNode, final String fieldName) {
        return optField(jsonNode, fieldName, JsonNode::asBoolean, false);
    }

    public static ArrayNode optArray(final JsonNode jsonNode, final String fieldName) {
        return optArray(jsonNode, fieldName, null);
    }

    public static ArrayNode optArray(final JsonNode jsonNode, final String fieldName, final ArrayNode fallback) {
        return optField(jsonNode, fieldName, valueNode -> valueNode.isArray() ? (ArrayNode) valueNode : fallback, fallback);
    }

    private static <T> T optField(final JsonNode jsonNode, final String fieldName,
                                  final Function<JsonNode, T> valueTransformer,
                                  final T fallback) {
        final JsonNode field = jsonNode.get(fieldName);
        if (field == null || field.isNull()) {
            return fallback;
        }

        return valueTransformer.apply(field);
    }

    private static <T> T optField(final JsonNode jsonNode, final int index,
                                  final Function<JsonNode, T> valueTransformer,
                                  final T fallback) {
        final JsonNode field = jsonNode.get(index);
        if (field == null || field.isNull()) {
            return fallback;
        }

        return valueTransformer.apply(field);
    }

    /**
     * An alternative to {@link JsonNode#toString()} that makes use of the customized {@link ObjectMapper}.
     *
     * @param value The value to serialize
     * @return The serialized valued
     * @throws RuntimeException When serialization failed
     */
    public static <T extends JsonNode> String toString(final T value) {
        try {
            return objectWriter().writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
