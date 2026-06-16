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
package org.dependencytrack.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;

/**
 * Enriches an OpenAPI spec's {@code info} block with the server release version.
 *
 * <p>The OpenAPI {@code version} field is part of the API contract and is intentionally left
 * untouched. Instead, the server version is appended to the {@code title} (so it is visible in
 * frontends such as Swagger UI / Redocly, which ignore custom fields) and exposed as a
 * machine-readable {@code x-server-version} extension.
 *
 * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/6414">Issue 6414</a>
 */
public final class OpenApiSpecEnricher {

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    private OpenApiSpecEnricher() {
    }

    /**
     * Enriches the {@code info} block of the given spec with the server version.
     *
     * @param specYaml      the OpenAPI spec as YAML
     * @param serverVersion the server release version (e.g. {@code 5.0.1})
     * @return the enriched spec as YAML, or the spec unchanged when {@code serverVersion} is blank
     * @throws IOException when the spec cannot be parsed
     */
    public static String enrich(final String specYaml, final String serverVersion) throws IOException {
        if (serverVersion == null || serverVersion.isBlank()) {
            return specYaml;
        }

        final JsonNode spec = YAML_MAPPER.readTree(specYaml);
        if (spec instanceof ObjectNode specNode && specNode.get("info") instanceof ObjectNode info) {
            final String title = info.path("title").asText("OWASP Dependency-Track");
            info.put("title", title + " (Server v" + serverVersion + ")");
            info.put("x-server-version", serverVersion);
        }

        return YAML_MAPPER.writeValueAsString(spec);
    }
}
