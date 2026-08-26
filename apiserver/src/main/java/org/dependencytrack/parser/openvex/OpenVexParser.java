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
package org.dependencytrack.parser.openvex;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.parser.openvex.model.Openvex;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parses bytes into {@link Openvex} documents.
 *
 * <p>Documents are first validated against the JSON Schema for version 0.2.0 of the
 * <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md">OpenVEX Specification</a>,
 * and then deserialized directly. All violations are collected before failing, so callers can
 * report every problem at once. Fields unknown to the supported specification version are ignored,
 * to remain forward-compatible.
 *
 * @since 5.7.0
 */
public final class OpenVexParser {

    /**
     * The only OpenVEX specification version supported by this parser.
     */
    static final String SUPPORTED_CONTEXT = "https://openvex.dev/ns/v0.2.0";

    private static final Pattern SPEC_VERSION_PATTERN = Pattern.compile("^https://openvex\\.dev/ns/v(\\d+\\.\\d+\\.\\d+)$");

    private static final Schema SCHEMA = SchemaRegistry
            .withDialect(Dialects.getDraft202012())
            .getSchema(OpenVexParser.class.getResourceAsStream("/schema/openvex.schema.json"));

    /**
     * Unlike the generated model classes, which do not declare {@code @JsonIgnoreProperties},
     * fields unknown to the supported specification version must be ignored, to remain
     * forward-compatible.
     */
    private static final ObjectMapper JSON_MAPPER = Mappers.jsonMapper()
            .copy()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private OpenVexParser() {
    }

    /**
     * @param vexBytes the raw OpenVEX document
     * @return the parsed document
     * @throws OpenVexParseException when the document is not valid JSON, or violates the OpenVEX specification
     */
    public static Openvex parse(final byte[] vexBytes) throws OpenVexParseException {
        final JsonNode documentNode;
        try {
            documentNode = JSON_MAPPER.readTree(vexBytes);
        } catch (IOException e) {
            throw new OpenVexParseException("VEX is not valid JSON", e);
        }

        if (!documentNode.isObject()) {
            throw new OpenVexParseException("Expected the OpenVEX document to be a JSON object, but it is not");
        }

        final List<Error> validationErrors = SCHEMA.validate(documentNode);
        if (!validationErrors.isEmpty()) {
            throw new OpenVexParseException(
                    "The uploaded VEX is not a valid OpenVEX document",
                    validationErrors.stream()
                            .map(OpenVexParser::formatValidationError)
                            .toList());
        }

        final Openvex document;
        try {
            // Schema validation guarantees that required fields are present and that
            // vocabularies are limited to the values defined by the specification.
            document = JSON_MAPPER.readValue(vexBytes, Openvex.class);
        } catch (IOException e) {
            // Unreachable for documents that passed validation; fail safe rather than
            // continuing with a partially populated document.
            throw new OpenVexParseException("Failed to deserialize VEX", e);
        }

        // Format assertions of the 2020-12 dialect are annotation-only by default,
        // so timestamp validity is verified here rather than through the schema.
        try {
            OffsetDateTime.parse(document.getTimestamp());
        } catch (DateTimeParseException e) {
            throw new OpenVexParseException(
                    "The uploaded VEX is not a valid OpenVEX document",
                    List.of("/timestamp: Not a valid ISO-8601 date-time: \"%s\"".formatted(document.getTimestamp())));
        }

        return document;
    }

    /**
     * The specification version a document conforms to, derived from its JSON-LD context.
     * For example, a context of {@code https://openvex.dev/ns/v0.2.0} yields {@code 0.2.0}.
     *
     * @return the specification version, or {@code null} if it cannot be derived from the context
     */
    public static @Nullable String specVersion(final Openvex document) {
        if (document.getContext() == null) {
            return null;
        }
        final var matcher = SPEC_VERSION_PATTERN.matcher(document.getContext());
        return matcher.matches() ? matcher.group(1) : null;
    }

    /**
     * Formats a schema validation error for display. The instance location is omitted when
     * the violation occurred at the document root, as there is nothing meaningful to point at.
     */
    private static String formatValidationError(final Error error) {
        final String location = String.valueOf(error.getInstanceLocation());
        if (location.isBlank()) {
            return error.getMessage();
        }
        return "%s: %s".formatted(location, error.getMessage());
    }

}
