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
package org.dependencytrack.resources.v1.openapi;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @since 4.11.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Parameters({
        @Parameter(
                name = "pageNumber",
                in = ParameterIn.QUERY,
                schema = @Schema(defaultValue = "1"),
                description = "The page to return. To be used in conjunction with <code>pageSize</code>."
        ),
        @Parameter(
                name = "pageSize",
                in = ParameterIn.QUERY,
                schema = @Schema(defaultValue = "100"),
                description = "Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>."
        ),
        @Parameter(
                name = "offset",
                in = ParameterIn.QUERY,
                description = "Offset to start returning elements from. To be used in conjunction with <code>limit</code>."
        ),
        @Parameter(
                name = "limit",
                in = ParameterIn.QUERY,
                description = "Number of elements to return per page. To be used in conjunction with <code>offset</code>."
        ),
        @Parameter(
                name = "sortName",
                in = ParameterIn.QUERY,
                description = "Name of the resource field to sort on."
        ),
        @Parameter(
                name = "sortOrder",
                in = ParameterIn.QUERY,
                schema = @Schema(allowableValues = "asc, desc"),
                description = "Ordering of items when sorting with <code>sortName</code>."
        )
})
public @interface PaginatedApi {
}
