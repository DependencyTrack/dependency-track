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
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RepositoryResponse(
        @Schema(description = "Type of the repository", requiredMode = Schema.RequiredMode.REQUIRED)
        RepositoryType type,
        @Schema(description = "Unique identifier of the repository within its type", requiredMode = Schema.RequiredMode.REQUIRED)
        String identifier,
        @Schema(description = "URL of the repository", requiredMode = Schema.RequiredMode.REQUIRED)
        String url,
        @Schema(description = "Order in which the repository is queried during version resolution", requiredMode = Schema.RequiredMode.REQUIRED)
        int resolutionOrder,
        @Schema(description = "Whether the repository is enabled", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean enabled,
        @Schema(description = "Whether the repository is internal to the organization")
        @Nullable Boolean internal,
        @Schema(description = "Whether the repository requires authentication", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean authenticationRequired,
        @Schema(description = "Username to authenticate with")
        @Nullable String username,
        @Schema(description = "Name of the secret holding the password or token")
        @Nullable String password,
        @Schema(description = "UUID of the repository", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static RepositoryResponse of(Repository repository) {
        return new RepositoryResponse(
                repository.getType(),
                repository.getIdentifier(),
                repository.getUrl(),
                repository.getResolutionOrder(),
                repository.isEnabled(),
                repository.isInternal(),
                repository.isAuthenticationRequired(),
                repository.getUsername(),
                repository.getPassword(),
                repository.getUuid());
    }

}
