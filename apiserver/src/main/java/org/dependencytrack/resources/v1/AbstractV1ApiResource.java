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
package org.dependencytrack.resources.v1;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.resources.AbstractApiResource;

import jakarta.ws.rs.core.Response;

/// @since 5.1.0
abstract class AbstractV1ApiResource extends AbstractApiResource {

    protected static final String TOTAL_COUNT_TYPE_HEADER = "X-Total-Count-Type";
    protected static final String TOTAL_COUNT_TYPE_HEADER_REF = "#/components/headers/TotalCountType";

    protected static Response.ResponseBuilder withTotalCountHeaders(
            Response.ResponseBuilder responseBuilder, Page.TotalCount totalCount) {
        return responseBuilder
                .header(TOTAL_COUNT_HEADER, totalCount.value())
                .header(TOTAL_COUNT_TYPE_HEADER, totalCount.type().name());
    }
}
