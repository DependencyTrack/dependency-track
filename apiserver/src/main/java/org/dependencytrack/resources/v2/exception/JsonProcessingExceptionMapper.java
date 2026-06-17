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

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import org.dependencytrack.api.v2.model.ProblemDetails;

import jakarta.ws.rs.ext.Provider;

/**
 * @since 5.0.0
 */
@Provider
public class JsonProcessingExceptionMapper extends LoggingProblemDetailsExceptionMapper<JsonProcessingException, ProblemDetails> {

    @Override
    ProblemDetails map(final JsonProcessingException exception) {
        if (exception instanceof InvalidDefinitionException
            || exception instanceof JsonGenerationException) {
            return super.map(exception);
        }

        return ProblemDetails.builder()
                .status(400)
                .title("JSON Processing Failed")
                .detail("The provided JSON could not be processed.")
                .build();
    }

}
