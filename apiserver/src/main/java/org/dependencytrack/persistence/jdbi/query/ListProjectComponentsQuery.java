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

/// @since 5.0.0
public record ListProjectComponentsQuery(
        long projectId,
        @Nullable Boolean onlyOutdated,
        @Nullable Boolean onlyDirect,
        @Nullable String searchText,
        boolean includeOccurrenceCount,
        int limit,
        @Nullable String pageToken,
        @Nullable SortBy sortBy,
        @Nullable SortDirection sortDirection) {

    public enum SortBy {
        NAME,
        GROUP,
        LAST_RISKSCORE,
        PUBLISHED_AT
    }

    public record PageToken(
            @Nullable Long lastId,
            @Nullable String lastName,
            @Nullable String lastGroup,
            @Nullable Double lastRiskScore,
            @Nullable Long lastPublishedAtMicros,
            @Nullable SortBy sortBy,
            @Nullable SortDirection sortDirection,
            Page.TotalCount totalCount) implements org.dependencytrack.common.pagination.PageToken {
    }

}
