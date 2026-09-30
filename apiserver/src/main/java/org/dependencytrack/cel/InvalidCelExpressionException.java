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
package org.dependencytrack.cel;

import dev.cel.common.CelIssue;
import dev.cel.common.CelValidationException;

import java.util.List;

/// @since 5.2.0
public final class InvalidCelExpressionException extends RuntimeException {

    public record Error(int line, int column, String message) {}

    private final List<Error> errors;

    public InvalidCelExpressionException(String message, List<Error> errors) {
        super(message);
        this.errors = List.copyOf(errors);
    }

    public InvalidCelExpressionException(String message, CelValidationException cause) {
        super(message, cause);
        this.errors = cause.getErrors().stream()
                .map(InvalidCelExpressionException::toError)
                .toList();
    }

    public List<Error> getErrors() {
        return errors;
    }

    private static Error toError(CelIssue issue) {
        return new Error(
                issue.getSourceLocation().getLine(), issue.getSourceLocation().getColumn(), issue.getMessage());
    }
}
