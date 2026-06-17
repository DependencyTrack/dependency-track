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

/**
 * @since 5.0.0
 */
public record ListProjectsConciseQuery(
        @Nullable String nameFilter,
        @Nullable String versionFilter,
        @Nullable String classifierFilter,
        @Nullable String tagFilter,
        @Nullable String teamFilter,
        @Nullable Boolean activeFilter,
        @Nullable Boolean onlyRootFilter,
        @Nullable UUID parentUuidFilter,
        @Nullable String searchText,
        boolean includeMetrics) {

    public ListProjectsConciseQuery() {
        this(null, null, null, null, null, null, null, null, null, false);
    }

    public ListProjectsConciseQuery withNameFilter(@Nullable String nameFilter) {
        return new ListProjectsConciseQuery(
                nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withVersionFilter(@Nullable String versionFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withClassifierFilter(@Nullable String classifierFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withTagFilter(@Nullable String tagFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withTeamFilter(@Nullable String teamFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withActiveFilter(@Nullable Boolean activeFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withOnlyRootFilter(@Nullable Boolean onlyRootFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withParentUuidFilter(@Nullable UUID parentUuidFilter) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                parentUuidFilter,
                this.searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withSearchText(@Nullable String searchText) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                searchText,
                this.includeMetrics);
    }

    public ListProjectsConciseQuery withIncludeMetrics(boolean includeMetrics) {
        return new ListProjectsConciseQuery(
                this.nameFilter,
                this.versionFilter,
                this.classifierFilter,
                this.tagFilter,
                this.teamFilter,
                this.activeFilter,
                this.onlyRootFilter,
                this.parentUuidFilter,
                this.searchText,
                includeMetrics);
    }

}
