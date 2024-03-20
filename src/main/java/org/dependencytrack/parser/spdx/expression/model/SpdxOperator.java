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
package org.dependencytrack.parser.spdx.expression.model;

/**
 * One of the SPDX expression operators as defined in the spec, together with their precedence.
 * 
 * @author hborchardt
 * @since 4.9.0
 */
public enum SpdxOperator {
    OR(1, "OR"), AND(2, "AND"), WITH(3, "WITH"), PLUS(4, "+");

    SpdxOperator(int precedence, String token) {
        this.precedence = precedence;
        this.token = token;
    }

    private final int precedence;
    private final String token;

    public int getPrecedence() {
        return precedence;
    }
    public String getToken() {
        return token;
    }
    @Override
    public String toString() {
        return this.token;
    }
}
