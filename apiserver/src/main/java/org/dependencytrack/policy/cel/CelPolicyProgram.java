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
package org.dependencytrack.policy.cel;

import dev.cel.common.types.CelType;
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public final class CelPolicyProgram {

    /// Maximum length of a violation message produced by an expression.
    /// Longer messages are truncated.
    static final int MAX_MESSAGE_LENGTH = 1024;

    /// Outcome of evaluating a policy expression.
    ///
    /// @param matched Whether the expression matched
    /// @param message Message produced by the expression, if it returned a string
    record Result(boolean matched, @Nullable String message) {

        private static final Result MATCHED = new Result(true, null);
        private static final Result NOT_MATCHED = new Result(false, null);
    }

    private final CelRuntime.Program program;
    private final Map<CelType, Set<String>> requirements;

    CelPolicyProgram(final CelRuntime.Program program, final Map<CelType, Set<String>> requirements) {
        this.program = program;
        this.requirements = requirements.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
    }

    Map<CelType, Set<String>> getRequirements() {
        return requirements;
    }

    /// Evaluate the expression.
    ///
    /// A boolean result is the match outcome. A string result means the expression
    /// matched and the string is the violation message, unless the string is blank,
    /// which is treated as no match. See ADR 043.
    Result evaluate(final Map<String, Object> arguments) throws CelEvaluationException {
        final Object result = program.eval(arguments);
        return switch (result) {
            case Boolean matched -> matched ? Result.MATCHED : Result.NOT_MATCHED;
            case String message -> {
                final String strippedMessage = message.strip();
                if (strippedMessage.isEmpty()) {
                    yield Result.NOT_MATCHED;
                }
                yield new Result(
                        true,
                        strippedMessage.length() > MAX_MESSAGE_LENGTH
                                ? strippedMessage.substring(0, MAX_MESSAGE_LENGTH)
                                : strippedMessage);
            }
            default ->
                throw new IllegalStateException("Expression returned unexpected type %s"
                        .formatted(result.getClass().getName()));
        };
    }

    boolean execute(final Map<String, Object> arguments) throws CelEvaluationException {
        return evaluate(arguments).matched();
    }
}
