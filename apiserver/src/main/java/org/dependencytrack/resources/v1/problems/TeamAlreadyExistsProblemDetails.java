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
package org.dependencytrack.resources.v1.problems;

import alpine.model.Team;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;

/**
 * @since 5.0.0
 */
public class TeamAlreadyExistsProblemDetails extends ProblemDetails {

    @Schema(description = "UUID of the existing team")
    private final UUID teamUuid;

    @Schema(description = "Name of the existing team")
    private final String teamName;

    public TeamAlreadyExistsProblemDetails(final Team team) {
        super(409, "Team already exists", "A team with the name \"%s\" already exists".formatted(team.getName()));
        this.teamUuid = team.getUuid();
        this.teamName = team.getName();
    }

    public UUID getTeamUuid() {
        return teamUuid;
    }

    public String getTeamName() {
        return teamName;
    }

}
