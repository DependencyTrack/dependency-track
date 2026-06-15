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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/// @since 5.1.0
@NullMarked
@JsonIgnoreProperties(ignoreUnknown = true)
public record CreatePolicyConditionRequest(
        @Schema(description = "Subject the condition evaluates", requiredMode = Schema.RequiredMode.REQUIRED)
        PolicyCondition.Subject subject,
        @Schema(description = "Operator used to compare the subject to the value", requiredMode = Schema.RequiredMode.REQUIRED)
        PolicyCondition.Operator operator,
        @NotBlank
        @Schema(description = "Value the subject is compared to", requiredMode = Schema.RequiredMode.REQUIRED)
        String value,
        @Schema(description = "Violation type produced when the condition matches. Required for `EXPRESSION` subjects")
        PolicyViolation.@Nullable Type violationType) {
}
