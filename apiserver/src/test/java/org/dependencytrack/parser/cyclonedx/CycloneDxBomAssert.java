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
package org.dependencytrack.parser.cyclonedx;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.AbstractAssert;

import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class CycloneDxBomAssert extends AbstractAssert<CycloneDxBomAssert, String> {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CycloneDxBomAssert(String actual) {
        super(actual, CycloneDxBomAssert.class);
    }

    public static CycloneDxBomAssert assertThatBom(String actual) {
        return new CycloneDxBomAssert(actual);
    }

    public CycloneDxBomAssert isValid() {
        isNotNull();

        assertThatNoException().isThrownBy(
                () -> CycloneDxValidator.getInstance().validate(actual.getBytes()));
        return this;
    }

    public CycloneDxBomAssert hasUniqueBomRefs() {
        isNotNull();

        final JsonNode bom;
        try {
            bom = MAPPER.readTree(actual);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }

        final var bomRefs = new ArrayList<String>();
        collectBomRefs(bom.at("/metadata/component"), bomRefs);
        bom.path("components").forEach(component -> collectBomRefs(component, bomRefs));
        bom.path("services").forEach(service -> collectBomRefs(service, bomRefs));
        bom.path("vulnerabilities").forEach(vuln -> collectBomRef(vuln, bomRefs));

        assertThat(bomRefs).doesNotHaveDuplicates();
        return this;
    }

    private static void collectBomRefs(JsonNode node, List<String> bomRefs) {
        collectBomRef(node, bomRefs);
        node.path("components").forEach(child -> collectBomRefs(child, bomRefs));
        node.path("services").forEach(child -> collectBomRefs(child, bomRefs));
    }

    private static void collectBomRef(JsonNode node, List<String> bomRefs) {
        final JsonNode bomRef = node.path("bom-ref");
        if (bomRef.isTextual()) {
            bomRefs.add(bomRef.asText());
        }
    }

}
