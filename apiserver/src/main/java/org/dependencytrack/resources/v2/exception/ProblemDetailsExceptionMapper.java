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

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;

/**
 * @since 5.0.0
 */
abstract class ProblemDetailsExceptionMapper<E extends Throwable, P extends ProblemDetails> implements ExceptionMapper<E> {

    abstract P map(E exception);

    @Override
    public Response toResponse(final E exception) {
        final P problemDetails = map(exception);

        return Response
                .status(problemDetails.getStatus())
                .header("Content-Type", "application/problem+json")
                .entity(problemDetails)
                .build();
    }

}
