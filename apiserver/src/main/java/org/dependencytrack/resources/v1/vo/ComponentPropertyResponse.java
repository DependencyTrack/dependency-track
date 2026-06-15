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
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.ComponentProperty;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ComponentPropertyResponse(
        @Schema(description = "Group the property belongs to")
        @Nullable String groupName,

        @Schema(description = "Name of the property", requiredMode = Schema.RequiredMode.REQUIRED)
        String propertyName,

        @Schema(description = "Value of the property")
        @Nullable String propertyValue,

        @Schema(description = "Type of the property", requiredMode = Schema.RequiredMode.REQUIRED)
        IConfigProperty.PropertyType propertyType,

        @Schema(description = "Description of the property")
        @Nullable String description,

        @Schema(description = "UUID of the property", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static ComponentPropertyResponse of(ComponentProperty property) {
        return new ComponentPropertyResponse(
                property.getGroupName(),
                property.getPropertyName(),
                property.getPropertyValue(),
                property.getPropertyType(),
                property.getDescription(),
                property.getUuid());
    }

}
