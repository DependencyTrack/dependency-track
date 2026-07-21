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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SortDirection;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.UUID;


public record ListAllProjectsQuery(
        @Nullable String nameContains,
        @Nullable String versionContains,
        @Nullable List<String> tags,
        @Nullable List<String> teams,
        @Nullable UUID parentUuid,
        @Nullable UUID ancestorUuid,
        @Nullable Boolean onlyRoot,
        @Nullable Boolean hasChildren,
        @Nullable Boolean isActive,
        @Nullable Boolean isLatest,
        @Nullable Instant lastBomImportSince,
        @Nullable Instant lastBomImportBefore,
        @Nullable List<String> severities,
        @Nullable List<String> classifiers,
        boolean includeMetrics,
        int limit,
        @Nullable String pageToken,
        @Nullable SortBy sortBy,
        @Nullable SortDirection sortDirection) {

    public enum SortBy {
        NAME,
        GROUP,
        VERSION,
        CLASSIFIER,
        INACTIVE_SINCE,
        IS_LATEST,
        LAST_BOM_IMPORTED,
        LAST_RISKSCORE
    }

    public record PageToken(
            long lastId,
            @Nullable String lastName,
            @Nullable String lastGroup,
            @Nullable String lastVersion,
            @Nullable String lastClassifier,
            @Nullable Instant lastInactiveSince,
            @Nullable Boolean lastIsLatest,
            @Nullable Instant lastBomImport,
            @Nullable Double lastInheritedRiskScore,
            @Nullable SortBy sortBy,
            @Nullable SortDirection sortDirection,
            Page.TotalCount totalCount) implements org.dependencytrack.common.pagination.PageToken {
    }

}
