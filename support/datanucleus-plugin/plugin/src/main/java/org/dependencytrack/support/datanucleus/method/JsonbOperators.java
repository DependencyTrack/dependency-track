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
package org.dependencytrack.support.datanucleus.method;

import org.datanucleus.store.query.expression.Expression.DyadicOperator;

/**
 * @see <a href="https://www.postgresql.org/docs/current/functions-json.html">JSON Functions and Operators</a>
 */
final class JsonbOperators {

    // '{"a":1, "b":2}'::jsonb @> '{"b":2}'::jsonb
    static final DyadicOperator JSONB_CONTAINS_JSONB = new DyadicOperator("@>", 1, false);

    private JsonbOperators() {
    }

}
