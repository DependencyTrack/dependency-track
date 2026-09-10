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

import alpine.model.MappedOidcGroup;
import io.swagger.v3.oas.annotations.media.Schema;
import org.jspecify.annotations.NullMarked;

import java.util.UUID;

/// @since 5.2.0
@NullMarked
public record MappedOidcGroupResponse(
        @Schema(description = "The mapped group", requiredMode = Schema.RequiredMode.REQUIRED)
        OidcGroupResponse group,

        @Schema(description = "UUID of the mapping", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static MappedOidcGroupResponse of(MappedOidcGroup mapping) {
        return new MappedOidcGroupResponse(OidcGroupResponse.of(mapping.getGroup()), mapping.getUuid());
    }
}
