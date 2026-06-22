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
package org.dependencytrack.resources.v1;

import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.media.Schema;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

class FindingOpenApiSchemaTest {

    @Test
    void shouldDescribeFindingResponse() throws IOException {
        final String spec;
        try (final var inputStream = FindingOpenApiSchemaTest.class
                .getResourceAsStream("/org/dependencytrack/api/v1/openapi.yaml")) {
            spec = new String(requireNonNull(inputStream).readAllBytes(), StandardCharsets.UTF_8);
        }

        final var parseResult = new OpenAPIParser().readContents(spec, null, null);
        assertThat(parseResult.getMessages()).isEmpty();

        final var openApi = parseResult.getOpenAPI();
        final Schema<?> responseSchema = openApi.getPaths()
                .get("/v1/finding/project/{uuid}")
                .getGet()
                .getResponses()
                .get("200")
                .getContent()
                .get("application/json")
                .getSchema();
        assertThat(responseSchema.getItems().get$ref()).isEqualTo("#/components/schemas/Finding");

        final var schemas = openApi.getComponents().getSchemas();
        assertThat(propertyNames(schemas.get("Finding")))
                .contains("component", "vulnerability", "analysis", "attribution", "matrix");
        assertThat(propertyNames(schemas.get("FindingComponent")))
                .contains("uuid", "name", "version", "project", "hasOccurrences");
        assertThat(propertyNames(schemas.get("FindingVulnerability")))
                .contains("uuid", "source", "vulnId", "severity", "cwes", "aliases");
        assertThat(propertyNames(schemas.get("FindingAnalysis")))
                .contains("state", "isSuppressed");
        assertThat(propertyNames(schemas.get("FindingAttribution")))
                .contains("analyzerIdentity", "attributedOn", "alternateIdentifier", "referenceUrl");
    }

    private static Set<String> propertyNames(final Schema<?> schema) {
        return schema.getProperties().keySet();
    }
}
