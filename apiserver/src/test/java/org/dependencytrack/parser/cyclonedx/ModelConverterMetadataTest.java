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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ModelConverterMetadataTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @ParameterizedTest
    @MethodSource("cycloneDxVersions")
    void shouldExportVersionAppropriateToolsMetadata(final Version version, final boolean expectsModernTools)
            throws Exception {
        final var bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);
        bom.setMetadata(ModelConverter.createMetadata(null, version));

        final String json = BomGeneratorFactory.createJson(version, bom).toJsonString();
        final String xml = BomGeneratorFactory.createXml(version, bom).toXmlString();

        final var validator = new CycloneDxValidator();
        assertThatNoException().isThrownBy(() -> validator.validate(json.getBytes(StandardCharsets.UTF_8)));
        assertThatNoException().isThrownBy(() -> validator.validate(xml.getBytes(StandardCharsets.UTF_8)));

        final JsonNode toolsNode = OBJECT_MAPPER.readTree(json).path("metadata").path("tools");
        final JsonNode toolNode;
        if (expectsModernTools) {
            assertThat(toolsNode.isObject()).isTrue();
            toolNode = toolsNode.path("components").path(0);
            assertThat(toolNode.path("type").asText()).isEqualTo("application");
            assertThat(toolNode.path("supplier").path("name").asText()).isEqualTo("OWASP");
            assertThat(xml)
                    .contains("<tools>", "<components>", "<component type=\"application\">", "<supplier>", "<name>OWASP</name>")
                    .doesNotContain("<tool>");
        } else {
            assertThat(toolsNode.isArray()).isTrue();
            toolNode = toolsNode.path(0);
            assertThat(toolNode.path("vendor").asText()).isEqualTo("OWASP");
            assertThat(xml)
                    .contains("<tools>", "<tool>", "<vendor>OWASP</vendor>")
                    .doesNotContain("<components>");
        }
        assertThat(toolNode.path("name").asText()).isNotBlank();
        assertThat(toolNode.path("version").asText()).isNotBlank();

        for (final Bom parsedBom : List.of(
                new JsonParser().parse(json.getBytes(StandardCharsets.UTF_8)),
                new XmlParser().parse(xml.getBytes(StandardCharsets.UTF_8)))) {
            final var importedMetadata = ModelConverter.convertToProjectMetadata(parsedBom.getMetadata());
            assertThat(importedMetadata.getTools().components()).satisfiesExactly(component -> {
                assertThat(component.getSupplier()).isNotNull();
                assertThat(component.getSupplier().getName()).isEqualTo("OWASP");
                assertThat(component.getName()).isEqualTo(toolNode.path("name").asText());
                assertThat(component.getVersion()).isEqualTo(toolNode.path("version").asText());
                if (expectsModernTools) {
                    assertThat(component.getClassifier()).isEqualTo(Classifier.APPLICATION);
                }
            });
            assertThat(importedMetadata.getTools().services()).isNull();
        }
    }

    private static Stream<Arguments> cycloneDxVersions() {
        return Stream.of(
                arguments(Version.VERSION_12, false),
                arguments(Version.VERSION_13, false),
                arguments(Version.VERSION_14, false),
                arguments(Version.VERSION_15, true),
                arguments(Version.VERSION_16, true));
    }
}
