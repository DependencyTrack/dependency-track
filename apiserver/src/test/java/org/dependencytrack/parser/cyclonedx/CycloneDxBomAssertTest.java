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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.parser.cyclonedx.CycloneDxBomAssert.assertThatBom;

class CycloneDxBomAssertTest {

    @Nested
    class HasUniqueBomRefsTest {

        @Test
        void shouldDetectDuplicateInNestedComponent() {
            assertThatThrownBy(() -> assertThatBom(/* language=JSON */ """
                    {
                      "bomFormat": "CycloneDX",
                      "specVersion": "1.7",
                      "metadata": {
                        "component": {
                          "type": "application",
                          "bom-ref": "root"
                        }
                      },
                      "components": [
                        {
                          "type": "library",
                          "bom-ref": "comp-a",
                          "components": [
                            { "type": "library", "bom-ref": "root" }
                          ]
                        }
                      ]
                    }
                    """).hasUniqueBomRefs())
                    .isInstanceOf(AssertionError.class)
                    .hasMessageContaining("root");
        }

        @Test
        void shouldIgnoreBomRefsThatAreNotDeclarations() {
            assertThatNoException().isThrownBy(() -> assertThatBom(/* language=JSON */ """
                    {
                      "bomFormat": "CycloneDX",
                      "specVersion": "1.7",
                      "components": [
                        {
                          "type": "library",
                          "bom-ref": "comp-a",
                          "patentAssertions": [
                            { "bom-ref": "patent-1", "assertionType": "use", "asserter": {} }
                          ]
                        },
                        {
                          "type": "library",
                          "bom-ref": "comp-b",
                          "patentAssertions": [
                            { "bom-ref": "patent-1", "assertionType": "use", "asserter": {} }
                          ]
                        }
                      ]
                    }
                    """).hasUniqueBomRefs());
        }

    }

}
