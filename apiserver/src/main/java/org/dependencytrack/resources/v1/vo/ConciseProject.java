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

import alpine.model.Team;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.ProjectDao.ConciseProjectListRow;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * @since 5.5.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Schema(description = "A concise representation of a project")
public record ConciseProject(
        @Schema(description = "UUID of the project", requiredMode = Schema.RequiredMode.REQUIRED) UUID uuid,
        @Schema(description = "Group or namespace of the project") String group,
        @Schema(description = "Name of the project", requiredMode = Schema.RequiredMode.REQUIRED) String name,
        @Schema(description = "Version of the project") String version,
        @Schema(description = "Classifier of the project") Classifier classifier,
        @Schema(description = "Whether the project is active", requiredMode = Schema.RequiredMode.REQUIRED) boolean active,
        @Schema(description = "Whether the project version is latest") boolean isLatest,
        @Schema(description = "Collection logic for aggregating child metrics") ProjectCollectionLogic collectionLogic,
        @Schema(description = "Tags associated with the project") List<Tag> tags,
        @Schema(description = "Teams associated with the project") List<Team> teams,
        @Schema(description = "Timestamp of the last BOM import") Date lastBomImport,
        @Schema(description = "Format of the last imported BOM") String lastBomImportFormat,
        @Schema(description = "Last observed risk score") Double lastRiskScore,
        @Schema(description = "Whether the project has children", requiredMode = Schema.RequiredMode.REQUIRED) boolean hasChildren,
        @Schema(description = "Latest metrics for the project") ConciseProjectMetrics metrics
) {

    public ConciseProject(final ConciseProjectListRow row) {
        this(row.uuid(), row.group(), row.name(), row.version(),
                row.classifier() != null ? Classifier.valueOf(row.classifier()) : null,
                row.inactiveSince() == null,
                row.isLatest(),
                row.collectionLogic(),
                convertTags(row.tags()),
                convertTeams(row.teams()),
                row.lastBomImport() != null ? Date.from(row.lastBomImport()) : null,
                row.lastBomImportFormat(),
                row.lastRiskScore(),
                row.hasChildren(),
                row.metrics() != null ? new ConciseProjectMetrics(row.metrics()) : null);
    }

    private static List<Tag> convertTags(final Collection<String> tagNames) {
        if (tagNames == null || tagNames.isEmpty()) {
            return Collections.emptyList();
        }

        return tagNames.stream()
                .map(tagName -> {
                    final var tag = new Tag();
                    tag.setName(tagName);
                    return tag;
                })
                .toList();
    }

    private static List<Team> convertTeams(final Collection<String> teamNames) {
        if (teamNames == null || teamNames.isEmpty()) {
            return Collections.emptyList();
        }

        return teamNames.stream()
                .map(teamName -> {
                    final var team = new Team();
                    team.setName(teamName);
                    return team;
                })
                .toList();
    }

}
