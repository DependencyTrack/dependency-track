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

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NullMarked;

import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonIgnoreProperties(ignoreUnknown = true)
public record UpdateLicenseGroupRequest(
        @NotNull
        @Schema(description = "UUID of the license group to update", requiredMode = Schema.RequiredMode.REQUIRED, format = "uuid")
        UUID uuid,
        @NotBlank
        @Size(min = 1, max = 255)
        @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "New name of the license group", requiredMode = Schema.RequiredMode.REQUIRED)
        String name) {
}
