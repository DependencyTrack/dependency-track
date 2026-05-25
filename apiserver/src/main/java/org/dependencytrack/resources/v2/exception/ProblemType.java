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
package org.dependencytrack.resources.v2.exception;

import jakarta.ws.rs.core.Response;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * @since 5.0.0
 */
@NullMarked
public enum ProblemType {

    INVALID_SORT_BY("invalid-sort-by", 400),
    VULN_DATA_SOURCE_MIRROR_ALREADY_RUNNING("vuln-data-source-mirror-already-running", 409),
    VULN_DATA_SOURCE_NOT_ENABLED("vuln-data-source-not-enabled", 400),
    VULN_POLICY_BUNDLE_SYNC_ALREADY_RUNNING("vuln-policy-bundle-sync-already-running", 409);

    private static final String PATH_PREFIX = "/problems/";

    private final String type;
    private final int status;
    private final String title;

    ProblemType(String slug, int status, @Nullable String title) {
        this.type = PATH_PREFIX + slug;
        this.status = status;
        if (title != null) {
            this.title = title;
        } else {
            final Response.Status responseStatus = Response.Status.fromStatusCode(status);
            if (responseStatus == null) {
                throw new IllegalArgumentException("No title specified for status code " + status);
            }
            this.title = responseStatus.getReasonPhrase();
        }
    }

    ProblemType(String slug, int status) {
        this(slug, status, null);
    }

    public String type() {
        return type;
    }

    public int status() {
        return status;
    }

    public String title() {
        return title;
    }

}
