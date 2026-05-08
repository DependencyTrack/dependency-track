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

/**
 * A token produced by the lexical analysis phase of SPDX expression parsing.
 *
 * @since 5.0.0
 */
sealed interface SpdxExpressionToken {

    record Identifier(String id) implements SpdxExpressionToken {

        @Override
        public String toString() {
            return id;
        }

    }

    record Operator(SpdxExpressionOperator operator) implements SpdxExpressionToken {

        @Override
        public String toString() {
            return operator.toString();
        }

    }

    enum Grouping implements SpdxExpressionToken {

        LEFT_PAREN {
            @Override
            public String toString() {
                return "(";
            }
        },

        RIGHT_PAREN {
            @Override
            public String toString() {
                return ")";
            }
        }

    }

}
