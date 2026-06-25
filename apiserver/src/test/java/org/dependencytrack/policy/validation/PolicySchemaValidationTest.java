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
package org.dependencytrack.policy.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import com.networknt.schema.serialization.DefaultNodeReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.apache.commons.io.IOUtils.resourceToString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicySchemaValidationTest {

    private static ObjectMapper yamlMapper;
    private static Schema schema;

    @BeforeAll
    static void beforeAll() {
        yamlMapper = new ObjectMapper(new YAMLFactory());
        schema = SchemaRegistry
                .withDialect(
                        Dialects.getDraft202012(),
                        builder -> builder
                                .nodeReader(DefaultNodeReader.builder()
                                        .yamlMapper(yamlMapper)
                                        .build()))
                .getSchema(PolicySchemaValidationTest.class.getResourceAsStream("/schema/vulnerability-policy-v1.schema.json"));
    }

    @Test
    void testValidPolicyYamlWithSchema() throws IOException {
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-valid.yaml", StandardCharsets.UTF_8);
        JsonNode jsonNode = yamlMapper.readTree(policyContent);
        List<Error> errors = schema.validate(jsonNode);
        assertTrue(errors.isEmpty());
    }

    @Test
    void testInvalidPolicyYamlWithSchema() throws IOException {
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-invalid.yaml", StandardCharsets.UTF_8);
        JsonNode jsonNode = yamlMapper.readTree(policyContent);
        List<Error> errors = schema.validate(jsonNode);
        assertThat(errors)
                .extracting(error -> "%s: %s".formatted(error.getInstanceLocation(), error.getMessage()))
                .containsExactlyInAnyOrder(
                        "/conditions: must have at most 1 items but found 2",
                        "/analysis/justification: does not have a value in the enumeration [\"CODE_NOT_PRESENT\", \"CODE_NOT_REACHABLE\", \"REQUIRES_CONFIGURATION\", \"REQUIRES_DEPENDENCY\", \"REQUIRES_ENVIRONMENT\", \"PROTECTED_BY_COMPILER\", \"PROTECTED_AT_RUNTIME\", \"PROTECTED_AT_PERIMETER\", \"PROTECTED_BY_MITIGATING_CONTROL\"]",
                        "/ratings/0/severity: does not have a value in the enumeration [\"CRITICAL\", \"HIGH\", \"MEDIUM\", \"LOW\", \"INFO\", \"UNASSIGNED\"]",
                        "/ratings/0/vector: does not match the regex pattern (SL:\\d/M:\\d/O:\\d/S:\\d/ED:\\d/EE:\\d/A:\\d/ID:\\d/LC:\\d/LI:\\d/LAV:\\d/LAC:\\d/FD:\\d/RD:\\d/NC:\\d/PV:\\d)|(AV:(N|A|L)\\/AC:(L|M|H)\\/A[Uu]:(N|S|M)\\/C:(N|P|C)\\/I:(N|P|C)\\/A:(N|P|C)|AV:(N|A|L|P)\\/AC:(L|H)\\/PR:(N|L|H)\\/UI:(N|R)\\/S:(U|C)\\/C:(N|L|H)\\/I:(N|L|H)\\/A:(N|L|H))|(AV:(N|A|L|P)\\/AC:(L|H)\\/PR:(N|L|H)\\/UI:(N|R)\\/S:(U|C)\\/C:(N|L|H)\\/I:(N|L|H)\\/A:(N|L|H)\\/E:(F|H|U|P|X)\\/RL:(W|U|T|O|X)\\/RC:(C|R|U|X)\\/CR:(X|L|M|H)\\/IR:(X|L|M|H)\\/AR:(X|L|M|H)\\/MAV:(X|N|A|L|P)\\/MAC:(X|L|H)\\/MPR:(X|N|L|H)\\/MUI:(X|N|R)\\/MS:(X|U|C)\\/MC:(X|N|L|H)\\/MI:(X|N|L|H)\\/MA:(X|N|L|H))",
                        "/ratings/0/score: string found, number expected"
                );
    }
}
