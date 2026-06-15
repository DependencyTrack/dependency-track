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
package org.dependencytrack.persistence.jdbi.query;

import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// @since 5.0.0
public record ListProjectsQuery(
        @Nullable String nameFilter,
        @Nullable String classifierFilter,
        @Nullable String tagFilter,
        @Nullable String teamFilter,
        @Nullable String notAssignedToTeamWithUuidFilter,
        @Nullable UUID parentUuidFilter,
        @Nullable UUID excludeDescendantsOfUuid,
        @Nullable String searchText,
        boolean excludeInactive,
        boolean onlyRoot,
        boolean includeMetrics) {

    public ListProjectsQuery() {
        this(null, null, null, null, null, null, null, null, false, false, false);
    }

    public ListProjectsQuery withNameFilter(@Nullable String nameFilter) {
        return new ListProjectsQuery(
                nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withClassifierFilter(@Nullable String classifierFilter) {
        return new ListProjectsQuery(
                this.nameFilter,
                classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withTagFilter(@Nullable String tagFilter) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withTeamFilter(@Nullable String teamFilter) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withNotAssignedToTeamWithUuidFilter(@Nullable String notAssignedToTeamWithUuidFilter) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withParentUuidFilter(@Nullable UUID parentUuidFilter) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withExcludeDescendantsOfUuid(@Nullable UUID excludeDescendantsOfUuid) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withSearchText(@Nullable String searchText) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                searchText,
                this.excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withExcludeInactive(boolean excludeInactive) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                excludeInactive,
                this.onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withOnlyRoot(boolean onlyRoot) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                onlyRoot,
                this.includeMetrics);
    }

    public ListProjectsQuery withIncludeMetrics(boolean includeMetrics) {
        return new ListProjectsQuery(
                this.nameFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.notAssignedToTeamWithUuidFilter,
                this.parentUuidFilter,
                this.excludeDescendantsOfUuid,
                this.searchText,
                this.excludeInactive,
                this.onlyRoot,
                includeMetrics);
    }

}
