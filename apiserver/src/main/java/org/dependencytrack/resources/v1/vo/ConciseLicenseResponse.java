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

import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.License;
import org.jspecify.annotations.NullMarked;

import java.util.UUID;

/// @since 5.1.0
@NullMarked
public record ConciseLicenseResponse(
        @Schema(description = "Display name of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,

        @Schema(description = "Identifier of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        String licenseId,

        @Schema(description = "Whether the license is approved by the OSI", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isOsiApproved,

        @Schema(description = "Whether the license is FSF libre", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isFsfLibre,

        @Schema(description = "Whether the licenseId has been deprecated by SPDX", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isDeprecatedLicenseId,

        @Schema(description = "Whether the license is a custom license created by a user", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isCustomLicense,

        @Schema(description = "UUID of the license", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static ConciseLicenseResponse of(License license) {
        return new ConciseLicenseResponse(
                license.getName(),
                license.getLicenseId(),
                license.isOsiApproved(),
                license.isFsfLibre(),
                license.isDeprecatedLicenseId(),
                license.isCustomLicense(),
                license.getUuid());
    }

}
