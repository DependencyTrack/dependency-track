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

import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;

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
@ApiImplicitParams({
        @ApiImplicitParam(
                name = "pageNumber",
                dataType = "int",
                paramType = "query",
                defaultValue = "1",
                value = "The page to return. To be used in conjunction with <code>pageSize</code>."
        ),
        @ApiImplicitParam(
                name = "pageSize",
                dataType = "int",
                paramType = "query",
                defaultValue = "100",
                value = "Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>."
        ),
        @ApiImplicitParam(
                name = "offset",
                dataType = "int",
                paramType = "query",
                value = "Offset to start returning elements from. To be used in conjunction with <code>limit</code>."
        ),
        @ApiImplicitParam(
                name = "limit",
                dataType = "int",
                paramType = "query",
                value = "Number of elements to return per page. To be used in conjunction with <code>offset</code>."
        ),
        @ApiImplicitParam(
                name = "sortName",
                dataType = "string",
                paramType = "query",
                value = "Name of the resource field to sort on."
        ),
        @ApiImplicitParam(
                name = "sortOrder",
                dataType = "string",
                paramType = "query",
                allowableValues = "asc, desc",
                value = "Ordering of items when sorting with <code>sortName</code>."
        )
})
public @interface PaginatedApi {
}
