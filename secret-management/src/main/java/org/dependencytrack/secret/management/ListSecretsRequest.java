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
package org.dependencytrack.secret.management;

import org.jspecify.annotations.Nullable;

/**
 * @param searchText Optional search text to filter secrets by.
 *                   Filtering is supposed to use case-insensitive
 *                   "starts with" semantics on the secret name.
 * @param pageToken  Optional page token to retrieve the next page of results.
 * @param limit      The maximum number of secrets to return.
 * @since 5.0.0
 */
public record ListSecretsRequest(
        @Nullable String searchText,
        @Nullable String pageToken,
        int limit) {

    public ListSecretsRequest {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than 0");
        }
    }

    public ListSecretsRequest() {
        this(null, null, 10);
    }

    public ListSecretsRequest withSearchText(@Nullable String searchText) {
        return new ListSecretsRequest(searchText, this.pageToken, this.limit);
    }

    public ListSecretsRequest withPageToken(@Nullable String pageToken) {
        return new ListSecretsRequest(this.searchText, pageToken, this.limit);
    }

    public ListSecretsRequest withLimit(int limit) {
        return new ListSecretsRequest(this.searchText, this.pageToken, limit);
    }

}
