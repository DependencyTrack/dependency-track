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

import alpine.model.IConfigProperty;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/// @since 5.1.0
@NullMarked
@JsonIgnoreProperties(ignoreUnknown = true)
public record CreateProjectPropertyRequest(
        @NotBlank
        @Size(min = 1, max = 255)
        @Pattern(regexp = "\\P{Cc}+", message = "The groupName must not contain control characters")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Group the property belongs to", requiredMode = Schema.RequiredMode.REQUIRED)
        String groupName,

        @NotBlank
        @Size(min = 1, max = 255)
        @Pattern(regexp = "\\P{Cc}+", message = "The propertyName must not contain control characters")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Name of the property", requiredMode = Schema.RequiredMode.REQUIRED)
        String propertyName,

        @Size(max = 1024)
        @Pattern(regexp = "\\P{Cc}+", message = "The propertyValue must not contain control characters")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Value of the property")
        @Nullable String propertyValue,

        @NotNull
        @Schema(description = "Type of the property", requiredMode = Schema.RequiredMode.REQUIRED)
        IConfigProperty.PropertyType propertyType,

        @Size(max = 255)
        @Pattern(regexp = "\\P{Cc}+", message = "The description must not contain control characters")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Description of the property")
        @Nullable String description) {
}
