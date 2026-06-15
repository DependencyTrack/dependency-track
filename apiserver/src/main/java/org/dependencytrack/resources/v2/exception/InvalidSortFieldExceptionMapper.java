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

import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.model.InvalidSortFieldProblemDetails;
import org.dependencytrack.exception.InvalidSortFieldException;

/// @since 5.0.0
@Provider
public final class InvalidSortFieldExceptionMapper extends ProblemDetailsExceptionMapper<InvalidSortFieldException, InvalidSortFieldProblemDetails> {

    @Override
    InvalidSortFieldProblemDetails map(InvalidSortFieldException exception) {
        return InvalidSortFieldProblemDetails.builder()
                .type(ProblemType.INVALID_SORT_FIELD.type())
                .status(ProblemType.INVALID_SORT_FIELD.status())
                .title(ProblemType.INVALID_SORT_FIELD.title())
                .detail(exception.getMessage())
                .invalidField(exception.getFieldName())
                .supportedFields(exception.getAllowedFieldNames())
                .build();
    }

}
