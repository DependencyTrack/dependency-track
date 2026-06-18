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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;

class OpenApiSpecEnricherTest {

    private static final String SPEC_YAML =
            """
            openapi: 3.0.1
            info:
              title: OWASP Dependency-Track API
              version: 2.0.0
            paths: {}
            """;

    @Test
    void shouldAppendServerVersionToTitleAndAddExtensionWithoutChangingApiVersion() throws Exception {
        final String enriched = OpenApiSpecEnricher.enrich(SPEC_YAML, "5.0.1");

        final JsonNode info = new ObjectMapper(new YAMLFactory()).readTree(enriched).get("info");
        assertThat(info.get("title").asText())
                .isEqualTo("OWASP Dependency-Track API (Server v5.0.1)");
        assertThat(info.get("x-server-version").asText()).isEqualTo("5.0.1");
        assertThat(info.get("version").asText()).isEqualTo("2.0.0");
    }

    @Test
    void shouldReturnSpecUnchangedWhenServerVersionIsBlank() throws Exception {
        assertThat(OpenApiSpecEnricher.enrich(SPEC_YAML, null)).isEqualTo(SPEC_YAML);
        assertThat(OpenApiSpecEnricher.enrich(SPEC_YAML, "   ")).isEqualTo(SPEC_YAML);
    }
}
