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
package org.dependencytrack.resources.v1.exception;

import org.dependencytrack.cel.InvalidCelExpressionException;
import org.dependencytrack.resources.v1.problems.InvalidNotificationFilterExpressionProblemDetails;
import org.dependencytrack.resources.v1.vo.CelExpressionError;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * @since 5.0.0
 */
@Provider
public final class InvalidCelExpressionExceptionMapper implements ExceptionMapper<InvalidCelExpressionException> {

    @Override
    public Response toResponse(InvalidCelExpressionException exception) {
        return new InvalidNotificationFilterExpressionProblemDetails(
                        400,
                        "Bad Request",
                        exception.getMessage(),
                        exception.getErrors().stream()
                                .map(e -> new CelExpressionError(e.line(), e.column(), e.message()))
                                .toList())
                .toResponse();
    }
}
