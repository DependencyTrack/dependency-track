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
package org.dependencytrack.exception;

import org.jspecify.annotations.Nullable;

import java.util.List;

import static java.util.Objects.requireNonNull;

/// @since 5.0.0
public final class InvalidSortFieldException extends IllegalArgumentException {

    private final String fieldName;
    private final List<String> allowedFieldNames;

    public InvalidSortFieldException(String fieldName, @Nullable List<String> allowedFieldNames) {
        super("Sorting by field '%s' is not supported".formatted(
                requireNonNull(fieldName, "fieldName must not be null")));
        this.fieldName = fieldName;
        this.allowedFieldNames = allowedFieldNames != null
                ? List.copyOf(allowedFieldNames)
                : null;
    }

    public InvalidSortFieldException(String fieldName) {
        this(fieldName, null);
    }

    public String getFieldName() {
        return fieldName;
    }

    public @Nullable List<String> getAllowedFieldNames() {
        return allowedFieldNames;
    }

}
