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
package org.dependencytrack.parser.spdx.expression;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public sealed interface SpdxExpression {

    /**
     * A leaf node representing an identifier (license ID, exception ID, or license ref).
     */
    record Identifier(String id) implements SpdxExpression {

        public Identifier {
            requireNonNull(id, "id must not be null");
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof Identifier(String otherId) && id.equalsIgnoreCase(otherId));
        }

        @Override
        public int hashCode() {
            return id.toLowerCase(Locale.ROOT).hashCode();
        }

        @Override
        public String toString() {
            return id;
        }

    }

    /**
     * An or-later expression ({@code +}), e.g. {@code GPL-2.0+}.
     */
    record OrLater(Identifier license) implements SpdxExpression {

        public OrLater {
            requireNonNull(license, "license must not be null");
        }

        @Override
        public String toString() {
            return "+(%s)".formatted(license);
        }

    }

    /**
     * A {@code WITH} expression, e.g. {@code GPL-2.0 WITH Classpath-exception-2.0}.
     */
    record With(SpdxExpression license, SpdxExpression exception) implements SpdxExpression {

        public With {
            requireNonNull(license, "license must not be null");
            requireNonNull(exception, "exception must not be null");
        }

        @Override
        public String toString() {
            return "WITH(%s, %s)".formatted(license, exception);
        }

    }

    /**
     * An {@code AND} expression with two or more operands.
     */
    record And(List<SpdxExpression> operands) implements SpdxExpression {

        private static final Comparator<SpdxExpression> OPERAND_COMPARATOR =
                Comparator.comparing(SpdxExpression::toString, String.CASE_INSENSITIVE_ORDER);

        public And {
            requireNonNull(operands, "operands must not be null");
            if (operands.size() < 2) {
                throw new IllegalArgumentException("AND requires at least 2 operands");
            }
            operands = operands.stream()
                    .sorted(OPERAND_COMPARATOR)
                    .toList();
        }

        @Override
        public String toString() {
            return "AND(%s)".formatted(
                    operands.stream()
                            .map(SpdxExpression::toString)
                            .collect(Collectors.joining(", ")));
        }

    }

    /**
     * An {@code OR} expression with two or more operands.
     */
    record Or(List<SpdxExpression> operands) implements SpdxExpression {

        private static final Comparator<SpdxExpression> OPERAND_COMPARATOR =
                Comparator.comparing(SpdxExpression::toString, String.CASE_INSENSITIVE_ORDER);

        public Or {
            requireNonNull(operands, "operands must not be null");
            if (operands.size() < 2) {
                throw new IllegalArgumentException("OR requires at least 2 operands");
            }
            operands = operands.stream()
                    .sorted(OPERAND_COMPARATOR)
                    .toList();
        }

        @Override
        public String toString() {
            return "OR(%s)".formatted(
                    operands.stream()
                            .map(SpdxExpression::toString)
                            .collect(Collectors.joining(", ")));
        }

    }

}
