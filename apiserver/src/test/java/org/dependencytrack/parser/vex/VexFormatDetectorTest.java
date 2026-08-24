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
package org.dependencytrack.parser.vex;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VexFormatDetectorTest {

    @Test
    void shouldDetectCycloneDxJson() {
        final byte[] vexBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1
                }
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(VexFormatDetector.detect(vexBytes)).isEqualTo(VexFormat.CYCLONEDX);
    }

    @Test
    void shouldDetectCycloneDxJsonWithLeadingWhitespace() {
        final byte[] vexBytes = """

                {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(VexFormatDetector.detect(vexBytes)).isEqualTo(VexFormat.CYCLONEDX);
    }

    @Test
    void shouldDetectCycloneDxXml() {
        final byte[] vexBytes = """
                <?xml version="1.0"?>
                <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"/>
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(VexFormatDetector.detect(vexBytes)).isEqualTo(VexFormat.CYCLONEDX);
    }

    @Test
    void shouldDetectCycloneDxXmlWithByteOrderMark() {
        final byte[] vexBytes = "\uFEFF<?xml version=\"1.0\"?>\n<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\" version=\"1\"/>"
                .getBytes(StandardCharsets.UTF_8);

        assertThat(VexFormatDetector.detect(vexBytes)).isEqualTo(VexFormat.CYCLONEDX);
    }

    @Test
    void shouldDetectOpenVexJson() {
        final byte[] vexBytes = /* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03.647787998-06:00",
                  "version": 1,
                  "statements": []
                }
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(VexFormatDetector.detect(vexBytes)).isEqualTo(VexFormat.OPENVEX);
    }

    @Test
    void shouldNotClassifyArbitraryJsonAsOpenVex() {
        final byte[] vexBytes = /* language=JSON */ """
                {
                  "@context": "https://www.w3.org/ns/activitystreams",
                  "type": "Create"
                }
                """.getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> VexFormatDetector.detect(vexBytes))
                .isInstanceOf(UnknownVexFormatException.class)
                .hasMessageContaining("Unable to identify");
    }

    @Test
    void shouldRejectArbitraryJson() {
        final byte[] vexBytes = /* language=JSON */ """
                {
                  "foo": "bar"
                }
                """.getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> VexFormatDetector.detect(vexBytes))
                .isInstanceOf(UnknownVexFormatException.class)
                .hasMessageContaining("Unable to identify")
                .hasMessageContaining("bomFormat")
                .hasMessageContaining("@context");
    }

    @Test
    void shouldRejectNonObjectJson() {
        assertThatThrownBy(() -> VexFormatDetector.detect("[1,2,3]".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(UnknownVexFormatException.class)
                .hasMessageContaining("Expected the document to be a JSON object");
    }

    @Test
    void shouldRejectInvalidJson() {
        assertThatThrownBy(() -> VexFormatDetector.detect("{invalid".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(UnknownVexFormatException.class)
                .hasMessageContaining("neither XML nor valid JSON");
    }

    @Test
    void shouldRejectEmptyDocument() {
        assertThatThrownBy(() -> VexFormatDetector.detect(new byte[0]))
                .isInstanceOf(UnknownVexFormatException.class)
                .hasMessageContaining("Expected the document to be a JSON object");
    }

}
