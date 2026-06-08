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
package org.dependencytrack.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

class AppliedPolicyAnnotationSerializationTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .findAndRegisterModules();

    @Test
    void serializesAppliedAtAsIso8601String() throws Exception {
        final var annotation = new AppliedPolicyAnnotation(
                "gem-policy-a",
                Instant.parse("2026-06-04T12:00:00Z"),
                "admin@localhost");

        final String json = objectMapper.writeValueAsString(annotation);

        assertThatJson(json).isEqualTo(/* language=JSON */ """
                {
                  "policyName": "gem-policy-a",
                  "appliedAt": "2026-06-04T12:00:00Z",
                  "annotator": "admin@localhost"
                }
                """);
    }

}
