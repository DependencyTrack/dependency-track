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

import com.networknt.schema.ValidationMessage;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.model.JsonSchemaValidationError;
import org.dependencytrack.api.v2.model.JsonSchemaValidationProblemDetails;
import org.dependencytrack.plugin.config.RuntimeConfigSchemaValidationException;

import java.util.ArrayList;

/**
 * @since 5.0.0
 */
@Provider
public final class RuntimeConfigSchemaValidationExceptionMapper
        extends ProblemDetailsExceptionMapper<RuntimeConfigSchemaValidationException, JsonSchemaValidationProblemDetails> {

    @Override
    public JsonSchemaValidationProblemDetails map(final RuntimeConfigSchemaValidationException exception) {
        final var errors = new ArrayList<JsonSchemaValidationError>(exception.getValidationMessages().size());

        for (final ValidationMessage validationMessage : exception.getValidationMessages()) {
            final var errorBuilder = JsonSchemaValidationError.builder()
                    .message(validationMessage.getMessage());

            if (validationMessage.getInstanceLocation() != null) {
                errorBuilder.instanceLocation(validationMessage.getInstanceLocation().toString());
            }
            if (validationMessage.getEvaluationPath() != null) {
                errorBuilder.evaluationPath(validationMessage.getEvaluationPath().toString());
            }
            if (validationMessage.getSchemaLocation() != null) {
                errorBuilder.schemaLocation(validationMessage.getSchemaLocation().toString());
            }
            if (validationMessage.getType() != null) {
                errorBuilder.keyword(validationMessage.getType());
            }

            errors.add(errorBuilder.build());
        }

        return JsonSchemaValidationProblemDetails.builder()
                .status(400)
                .title("JSON Schema Validation Failed")
                .detail("The provided configuration failed JSON schema validation.")
                .errors(errors)
                .build();
    }

}
