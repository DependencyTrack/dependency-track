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
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.serialization.DefaultJsonNodeReader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.apache.commons.io.IOUtils.resourceToString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PolicySchemaValidationTest {

    @Test
    public void testValidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final String jsonSchemaContent = resourceToString("/schema/vulnerability-policy-v1.schema.json", StandardCharsets.UTF_8);
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-valid.yaml", StandardCharsets.UTF_8);
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(DefaultJsonNodeReader.builder().jsonMapper(objMapper).build())
                .build();
        JsonSchema schema = factory.getSchema(jsonSchemaContent);
        JsonNode jsonNode = objMapper.readTree(policyContent);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertTrue(validateMsg.isEmpty());
    }

    @Test
    public void testInvalidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final String jsonSchemaContent = resourceToString("/schema/vulnerability-policy-v1.schema.json", StandardCharsets.UTF_8);
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-invalid.yaml", StandardCharsets.UTF_8);
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(DefaultJsonNodeReader.builder().jsonMapper(objMapper).build())
                .build();
        JsonSchema schema = factory.getSchema(jsonSchemaContent);
        JsonNode jsonNode = objMapper.readTree(policyContent);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertThat(validateMsg).satisfiesExactlyInAnyOrder(
                error -> assertThat(error.getMessage()).isEqualTo("$.conditions: must have at most 1 items but found 2"),
                error -> assertThat(error.getMessage()).isEqualTo("$.analysis.justification: does not have a value in the enumeration [\"CODE_NOT_PRESENT\", \"CODE_NOT_REACHABLE\", \"REQUIRES_CONFIGURATION\", \"REQUIRES_DEPENDENCY\", \"REQUIRES_ENVIRONMENT\", \"PROTECTED_BY_COMPILER\", \"PROTECTED_AT_RUNTIME\", \"PROTECTED_AT_PERIMETER\", \"PROTECTED_BY_MITIGATING_CONTROL\"]"),
                error -> assertThat(error.getMessage()).isEqualTo("$.ratings[0].severity: does not have a value in the enumeration [\"CRITICAL\", \"HIGH\", \"MEDIUM\", \"LOW\", \"INFO\", \"UNASSIGNED\"]"),
                error -> assertThat(error.getMessage()).contains("$.ratings[0].vector: does not match the regex pattern (SL:\\d/M:\\d/O:\\d/S:\\d/ED:\\d/EE:\\d/A:\\d/ID:\\d/LC:\\d/LI:\\d/LAV:\\d/LAC:\\d/FD:\\d/RD:\\d/NC:\\d/PV:\\d)|(AV:(N|A|L)\\/AC:(L|M|H)\\/A[Uu]:(N|S|M)\\/C:(N|P|C)\\/I:(N|P|C)\\/A:(N|P|C)|AV:(N|A|L|P)\\/AC:(L|H)\\/PR:(N|L|H)\\/UI:(N|R)\\/S:(U|C)\\/C:(N|L|H)\\/I:(N|L|H)\\/A:(N|L|H))|(AV:(N|A|L|P)\\/AC:(L|H)\\/PR:(N|L|H)\\/UI:(N|R)\\/S:(U|C)\\/C:(N|L|H)\\/I:(N|L|H)\\/A:(N|L|H)\\/E:(F|H|U|P|X)\\/RL:(W|U|T|O|X)\\/RC:(C|R|U|X)\\/CR:(X|L|M|H)\\/IR:(X|L|M|H)\\/AR:(X|L|M|H)\\/MAV:(X|N|A|L|P)\\/MAC:(X|L|H)\\/MPR:(X|N|L|H)\\/MUI:(X|N|R)\\/MS:(X|U|C)\\/MC:(X|N|L|H)\\/MI:(X|N|L|H)\\/MA:(X|N|L|H)"),
                error -> assertThat(error.getMessage()).isEqualTo("$.ratings[0].score: string found, number expected")
        );
    }
}
