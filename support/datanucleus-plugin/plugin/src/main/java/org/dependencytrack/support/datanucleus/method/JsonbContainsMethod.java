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

import org.datanucleus.exceptions.NucleusException;
import org.datanucleus.store.rdbms.sql.SQLStatement;
import org.datanucleus.store.rdbms.sql.expression.BooleanExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLExpression;
import org.datanucleus.store.rdbms.sql.expression.StringExpression;

import java.util.List;

public class JsonbContainsMethod extends AbstractJsonbMethod {

    @Override
    public SQLExpression getExpression(final SQLStatement stmt, final SQLExpression expr, final List<SQLExpression> args) {
        if (!(expr instanceof StringExpression)) {
            throw new NucleusException("Cannot invoke jsonbContains on expression of type %s"
                    .formatted(expr.getClass().getName()));
        }
        if (args == null || args.size() != 1) {
            throw new NucleusException("jsonbContains requires exactly one argument");
        }
        if (!(args.getFirst() instanceof final StringExpression argStringExpression)) {
            throw new NucleusException("Cannot invoke jsonbContains with argument of type %s"
                    .formatted(args.getFirst().getClass().getName()));
        }

        // TODO: Is there a reliable way to check whether expr has the SQL type JSONB?

        //
        return new BooleanExpression(expr, JsonbOperators.JSONB_CONTAINS_JSONB, castAsJsonb(stmt, argStringExpression));
    }

}
