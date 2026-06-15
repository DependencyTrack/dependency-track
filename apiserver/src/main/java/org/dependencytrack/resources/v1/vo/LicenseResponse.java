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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.License;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LicenseResponse(
        @Schema(description = "Display name of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,

        @Schema(description = "Identifier of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String licenseId,

        @Schema(description = "Full license text")
        @Nullable String licenseText,

        @Schema(description = "Standard license template used to derive the license text")
        @Nullable String standardLicenseTemplate,

        @Schema(description = "Standard license header typically added to the top of source code")
        @Nullable String standardLicenseHeader,

        @Schema(description = "Comments about the license")
        @Nullable String licenseComments,

        @Schema(description = "Whether the license is approved by the OSI", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isOsiApproved,

        @Schema(description = "Whether the license is FSF libre", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isFsfLibre,

        @Schema(description = "Whether the licenseId has been deprecated by SPDX", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isDeprecatedLicenseId,

        @Schema(description = "Whether the license is a custom license created by a user", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isCustomLicense,

        @Schema(description = "Additional URLs with information about the license")
        @Nullable List<String> seeAlso,

        @Schema(description = "License groups the license belongs to", requiredMode = Schema.RequiredMode.REQUIRED)
        List<LicenseGroup> licenseGroups,

        @Schema(description = "UUID of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public record LicenseGroup(
            @Schema(description = "UUID of the license group", requiredMode = Schema.RequiredMode.REQUIRED)
            UUID uuid,

            @Schema(description = "Name of the license group", requiredMode = Schema.RequiredMode.REQUIRED)
            String name) {

        public static LicenseGroup of(org.dependencytrack.model.LicenseGroup licenseGroup) {
            return new LicenseGroup(licenseGroup.getUuid(), licenseGroup.getName());
        }

    }

    public static LicenseResponse of(License license) {
        // NB: The API originally returned JDO models directly, and JDO populates loaded-but-empty
        // fields as empty lists, not null. This DTO replicates that behaviour for backward-compat.
        final List<org.dependencytrack.model.LicenseGroup> jdoGroups = license.getLicenseGroups();
        final List<LicenseGroup> groups = jdoGroups != null
                ? jdoGroups.stream().map(LicenseGroup::of).toList()
                : List.of();

        return new LicenseResponse(
                license.getName(),
                license.getLicenseId(),
                license.getText(),
                license.getTemplate(),
                license.getHeader(),
                license.getComment(),
                license.isOsiApproved(),
                license.isFsfLibre(),
                license.isDeprecatedLicenseId(),
                license.isCustomLicense(),
                license.getSeeAlso() != null
                        ? List.of(license.getSeeAlso())
                        : null,
                groups,
                license.getUuid());
    }

}
