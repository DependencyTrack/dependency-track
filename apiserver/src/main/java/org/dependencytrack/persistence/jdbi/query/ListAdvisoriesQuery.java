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

/**
 * @since 5.0.0
 */
public record ListAdvisoriesQuery(
        @Nullable String format,
        @Nullable String searchText,
        @Nullable String pageToken,
        int limit) {

    public ListAdvisoriesQuery() {
        this(null, null, null, 100);
    }

    public ListAdvisoriesQuery withFormat(@Nullable String format) {
        return new ListAdvisoriesQuery(format, this.searchText, this.pageToken, this.limit);
    }

    public ListAdvisoriesQuery withSearchText(@Nullable String searchText) {
        return new ListAdvisoriesQuery(this.format, searchText, this.pageToken, this.limit);
    }

    public ListAdvisoriesQuery withPageToken(@Nullable String pageToken) {
        return new ListAdvisoriesQuery(this.format, this.searchText, pageToken, this.limit);
    }

    public ListAdvisoriesQuery withLimit(int limit) {
        return new ListAdvisoriesQuery(this.format, this.searchText, this.pageToken, limit);
    }

}
