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

import java.util.Set;

import org.dependencytrack.model.validation.ValidUuid;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record TeamsSetRequest(
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
        @NotBlank
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The username may only contain printable characters")
        String username,

        @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
        @NotNull
        Set<@ValidUuid String> teams) {
}
