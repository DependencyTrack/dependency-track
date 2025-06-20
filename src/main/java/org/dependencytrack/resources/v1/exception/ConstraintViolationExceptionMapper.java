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

import alpine.server.resources.AlpineResource;
import org.apache.commons.lang3.StringUtils;
import org.glassfish.jersey.server.validation.ValidationError;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * An {@link ExceptionMapper} for {@link ConstraintViolationException}s.
 * <p>
 * This mapper allows for Jersey resource parameter validation to be used,
 * while staying consistent with the response format returned by Alpine's
 * {@link AlpineResource#failOnValidationError(Set[])}, which is used for
 * validation entire objects.
 *
 * @since 4.11.0
 */
@Provider
@SuppressWarnings("JavadocReference")
public class ConstraintViolationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    @Override
    public Response toResponse(final ConstraintViolationException exception) {
        final List<ValidationError> errors = mapToValidationErrors(exception.getConstraintViolations());

        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errors)
                .build();
    }

    /**
     * Copied from {@link AlpineResource#contOnValidationError(Set[])}.
     *
     * @param violations A {@link Collection} or one or more {@link ConstraintViolation}s
     * @return A {@link List} of zero or more {@link ValidationError}s
     * @see <a href="https://github.com/stevespringett/Alpine/blob/76f5bfd6b2d9469e8a42ba360b3b3feef7a87a8b/alpine-server/src/main/java/alpine/server/resources/AlpineResource.java#L155-L190">Source</a>
     */
    private static List<ValidationError> mapToValidationErrors(final Collection<ConstraintViolation<?>> violations) {
        final List<ValidationError> errors = new ArrayList<>(violations.size());

        for (final ConstraintViolation<?> violation : violations) {
            if (violation.getPropertyPath().iterator().next().getName() != null) {
                final String path = violation.getPropertyPath() != null ? violation.getPropertyPath().toString() : null;
                final String message = violation.getMessage() != null ? StringUtils.removeStart(violation.getMessage(), path + ".") : null;
                final String messageTemplate = violation.getMessageTemplate();
                final String invalidValue = violation.getInvalidValue() != null ? violation.getInvalidValue().toString() : null;
                final ValidationError error = new ValidationError(message, messageTemplate, path, invalidValue);
                errors.add(error);
            }
        }

        return errors;
    }

}
