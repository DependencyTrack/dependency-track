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

import org.dependencytrack.api.v2.model.ProblemDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.ServerErrorException;

/**
 * @since 5.0.0
 */
abstract class LoggingProblemDetailsExceptionMapper<E extends Exception, P extends ProblemDetails> extends ProblemDetailsExceptionMapper<E, P> {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    @SuppressWarnings("unchecked")
    P map(final E exception) {
        if (exception instanceof final ProblemDetailsException pde) {
            // Already has properly mapped problem details. Nothing to do here.
            return (P) pde.getProblemDetails();
        }

        logger.error("Uncaught exception occurred during request processing", exception);

        final int status = exception instanceof final ServerErrorException see
                ? see.getResponse().getStatus()
                : 500;

        return (P) ProblemDetails.builder()
                .status(status)
                .title("Unexpected error")
                .detail("An error occurred that was not anticipated.")
                .build();
    }

}
