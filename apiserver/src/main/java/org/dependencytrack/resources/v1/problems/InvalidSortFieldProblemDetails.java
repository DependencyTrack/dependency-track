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
package org.dependencytrack.resources.v1.problems;

import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.resources.v2.exception.ProblemType;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.List;

import static java.util.Objects.requireNonNull;

/// @since 5.0.0
@NullMarked
public final class InvalidSortFieldProblemDetails extends ProblemDetails {

    @Schema(
            description = "Name of the field for which sorting is not supported.",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private final String invalidField;

    @Schema(
            description = """
                    Names of fields for which sorting is supported. \
                    When empty, sorting is explicitly *not* supported. \
                    When absent, sorting may be supported, but no definitive guarantees exist. \
                    Consult the operation's description.\
                    """
    )
    private final @Nullable List<String> supportedFields;

    public InvalidSortFieldProblemDetails(String invalidField, @Nullable List<String> supportedFields) {
        this.invalidField = requireNonNull(invalidField, "invalidField must not be null");
        this.supportedFields = supportedFields != null ? List.copyOf(supportedFields) : null;
        this.setType(URI.create(ProblemType.INVALID_SORT_FIELD.type()));
        this.setStatus(ProblemType.INVALID_SORT_FIELD.status());
        this.setTitle(ProblemType.INVALID_SORT_FIELD.title());
    }

    public String getInvalidField() {
        return invalidField;
    }

    public @Nullable List<String> getSupportedFields() {
        return supportedFields;
    }

}
