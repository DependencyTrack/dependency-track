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
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

/// @since 5.1.0
@NullMarked
@JsonIgnoreProperties(ignoreUnknown = true)
public record CreateLicenseRequest(
        @NotBlank
        @Size(min = 1, max = 255)
        @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
        @Schema(description = "Display name of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,

        @NotBlank
        @Size(min = 1, max = 255)
        @Pattern(regexp = RegexSequence.Definition.STRING_IDENTIFIER, message = "The licenseId may only contain alpha, numeric, and specific symbols _-.+")
        @JsonAlias("licenseExceptionId")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Identifier of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String licenseId,

        @JsonAlias("licenseExceptionText")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Full license text")
        @Nullable String licenseText,

        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Standard license header typically added to the top of source code")
        @Nullable String standardLicenseHeader,

        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Standard license template used to derive the license text")
        @Nullable String standardLicenseTemplate,

        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Schema(description = "Comments about the license")
        @Nullable String licenseComments,

        @JsonDeserialize(contentUsing = TrimmedStringDeserializer.class)
        @Schema(description = "Additional URLs with information about the license")
        @Nullable List<String> seeAlso,

        @Schema(description = "Whether the license is approved by the OSI")
        @Nullable Boolean isOsiApproved,

        @Schema(description = "Whether the license is FSF libre")
        @Nullable Boolean isFsfLibre,

        @Schema(description = "Whether the licenseId has been deprecated by SPDX")
        @Nullable Boolean isDeprecatedLicenseId) {
}
