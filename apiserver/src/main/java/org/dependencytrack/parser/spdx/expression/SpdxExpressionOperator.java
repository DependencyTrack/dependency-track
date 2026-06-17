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

import org.jspecify.annotations.Nullable;

/**
 * One of the SPDX expression operators as defined in the spec.
 *
 * @author hborchardt
 * @since 4.9.0
 */
public enum SpdxExpressionOperator {

    OR("OR"),
    AND("AND"),
    WITH("WITH"),
    PLUS("+");

    private final String token;

    SpdxExpressionOperator(String token) {
        this.token = token;
    }

    public static @Nullable SpdxExpressionOperator ofToken(String token) {
        for (final SpdxExpressionOperator op : values()) {
            // NB: The spec dictates case-sensitive uppercase operators,
            // but enforcing that may be too strict given we're dealing
            // with data we don't control.
            if (op.token.equalsIgnoreCase(token)) {
                return op;
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return this.token;
    }

}