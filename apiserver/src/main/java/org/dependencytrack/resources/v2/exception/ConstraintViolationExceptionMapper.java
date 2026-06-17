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

import org.dependencytrack.api.v2.model.ConstraintViolationError;
import org.dependencytrack.api.v2.model.InvalidRequestProblemDetails;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.ArrayList;
import java.util.Set;

/**
 * @since 5.0.0
 */
@Provider
public final class ConstraintViolationExceptionMapper extends ProblemDetailsExceptionMapper<ConstraintViolationException, InvalidRequestProblemDetails> {

    @Override
    public InvalidRequestProblemDetails map(final ConstraintViolationException exception) {
        final Set<ConstraintViolation<?>> violations = exception.getConstraintViolations();

        final var errors = new ArrayList<ConstraintViolationError>(violations.size());

        for (final ConstraintViolation<?> violation : violations) {
            errors.add(
                    ConstraintViolationError.builder()
                            .path(violation.getPropertyPath().toString())
                            .value(violation.getInvalidValue() != null
                                    ? violation.getInvalidValue().toString()
                                    : null)
                            .message(violation.getMessage())
                            .build());
        }

        return InvalidRequestProblemDetails.builder()
                .status(Response.Status.BAD_REQUEST.getStatusCode())
                .title("Bad Request")
                .detail("The request could not be processed because it failed validation.")
                .errors(errors)
                .build();
    }

}
