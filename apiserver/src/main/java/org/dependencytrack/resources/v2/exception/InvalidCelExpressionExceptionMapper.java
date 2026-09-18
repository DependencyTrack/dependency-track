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

import org.dependencytrack.api.v2.model.CelExpressionError;
import org.dependencytrack.api.v2.model.InvalidCelExpressionProblemDetails;
import org.dependencytrack.cel.InvalidCelExpressionException;

import jakarta.ws.rs.ext.Provider;

/// @since 5.2.0
@Provider
public final class InvalidCelExpressionExceptionMapper
        extends ProblemDetailsExceptionMapper<InvalidCelExpressionException, InvalidCelExpressionProblemDetails> {

    @Override
    InvalidCelExpressionProblemDetails map(InvalidCelExpressionException exception) {
        return InvalidCelExpressionProblemDetails.builder()
                .status(400)
                .title("Bad Request")
                .detail(exception.getMessage())
                .errors(exception.getErrors().stream()
                        .<CelExpressionError>map(error -> CelExpressionError.builder()
                                .line(error.line())
                                .column(error.column())
                                .message(error.message())
                                .build())
                        .toList())
                .build();
    }
}
