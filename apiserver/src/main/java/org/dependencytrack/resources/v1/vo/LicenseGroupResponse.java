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
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.LicenseGroup;
import org.jspecify.annotations.NullMarked;

import java.util.List;
import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LicenseGroupResponse(
        @Schema(description = "Name of the license group", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "Licenses belonging to the license group", requiredMode = Schema.RequiredMode.REQUIRED)
        List<License> licenses,
        @Schema(description = "Risk weight assigned to violations of this group", requiredMode = Schema.RequiredMode.REQUIRED)
        int riskWeight,
        @Schema(description = "UUID of the license group", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static LicenseGroupResponse of(LicenseGroup group) {
        // NB: The API originally returned JDO models directly, and JDO populates loaded-but-empty
        // fields as empty lists, not null. This DTO replicates that behaviour for backward-compat.
        final List<org.dependencytrack.model.License> jdoLicenses = group.getLicenses();
        final List<License> licenses = jdoLicenses != null
                ? jdoLicenses.stream().map(License::of).toList()
                : List.of();

        return new LicenseGroupResponse(
                group.getName(),
                licenses,
                group.getRiskWeight(),
                group.getUuid());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record License(
            @Schema(description = "Name of the license", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "SPDX license identifier", requiredMode = Schema.RequiredMode.REQUIRED)
            String licenseId,
            @JsonProperty("isOsiApproved")
            @Schema(description = "Whether the license is OSI-approved", requiredMode = Schema.RequiredMode.REQUIRED)
            boolean osiApproved,
            @JsonProperty("isFsfLibre")
            @Schema(description = "Whether the license is FSF Libre", requiredMode = Schema.RequiredMode.REQUIRED)
            boolean fsfLibre,
            @JsonProperty("isDeprecatedLicenseId")
            @Schema(description = "Whether the license identifier has been deprecated by SPDX", requiredMode = Schema.RequiredMode.REQUIRED)
            boolean deprecatedLicenseId,
            @JsonProperty("isCustomLicense")
            @Schema(description = "Whether the license is custom (user-defined)", requiredMode = Schema.RequiredMode.REQUIRED)
            boolean customLicense,
            @Schema(description = "UUID of the license", requiredMode = Schema.RequiredMode.REQUIRED)
            UUID uuid) {

        public static License of(org.dependencytrack.model.License jdo) {
            return new License(
                    jdo.getName(),
                    jdo.getLicenseId(),
                    jdo.isOsiApproved(),
                    jdo.isFsfLibre(),
                    jdo.isDeprecatedLicenseId(),
                    jdo.isCustomLicense(),
                    jdo.getUuid());
        }
    }

}
