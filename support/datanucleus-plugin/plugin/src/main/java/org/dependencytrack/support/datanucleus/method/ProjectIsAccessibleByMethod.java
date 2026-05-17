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

import org.datanucleus.store.rdbms.mapping.java.JavaTypeMapping;
import org.datanucleus.store.rdbms.sql.SQLStatement;
import org.datanucleus.store.rdbms.sql.expression.ArrayLiteral;
import org.datanucleus.store.rdbms.sql.expression.BooleanExpression;
import org.datanucleus.store.rdbms.sql.expression.IntegerLiteral;
import org.datanucleus.store.rdbms.sql.expression.ObjectExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLLiteral;
import org.datanucleus.store.rdbms.sql.method.SQLMethod;

import java.util.List;
import java.util.StringJoiner;

/**
 * @since 5.0.0
 */
public class ProjectIsAccessibleByMethod implements SQLMethod {

    private static final String PROJECT_CLASS_NAME = "org.dependencytrack.model.Project";

    @Override
    public SQLExpression getExpression(
            SQLStatement stmt,
            SQLExpression expr,
            List<SQLExpression> args) {
        if (!(expr instanceof final ObjectExpression objectExpr))
            // DataNucleus should prevent this from ever happening since
            // the method is explicitly registered for java.lang.Object.
            throw new IllegalStateException("Expected expression to be of type %s, but got: %s".formatted(
                    ObjectExpression.class.getName(), expr.getClass().getName()));

        final String objectTypeName = objectExpr.getJavaTypeMapping().getType();
        if (!PROJECT_CLASS_NAME.equals(objectTypeName))
            throw new IllegalStateException(
                    "isAccessibleBy is only allowed for objects of type %s, but was called on %s".formatted(
                            PROJECT_CLASS_NAME, objectTypeName));

        if (args == null) {
            throw new IllegalArgumentException();
        } else if (args.size() != 1) {
            throw new IllegalArgumentException("Expected exactly one argument, but got " + args.size());
        }

        // TODO: When a list, set, etc. is passed as argument, it will be of type CollectionLiteral.
        //  Array literals are easier to verify the type of, hence we're focusing on that for now.

        return switch (args.getFirst()) {
            case IntegerLiteral userIdArg -> getUserExpression(stmt, objectExpr, userIdArg);
            case ArrayLiteral arrayLiteralArg -> getApiKeyExpression(stmt, objectExpr, arrayLiteralArg);
            default -> throw new IllegalArgumentException(
                    "Expected argument to be of type %s or %s, but got %s".formatted(
                            ArrayLiteral.class.getName(),
                            IntegerLiteral.class.getName(),
                            args.getFirst().getClass().getName()));
        };
    }

    private SQLExpression getApiKeyExpression(
            SQLStatement stmt,
            ObjectExpression objectExpr,
            ArrayLiteral arrayLiteralArg) {
        if (!(arrayLiteralArg.getValue() instanceof final Long[] teamIds)) {
            throw new IllegalArgumentException(
                    "Expected array argument to be of type %s, but got %s".formatted(
                            Long[].class.getName(),
                            arrayLiteralArg.getValue().getClass().getName()));
        }

        final JavaTypeMapping booleanTypeMapping = stmt.getSQLExpressionFactory().getMappingForType(Boolean.class);

        // Inline the team IDs as a Postgres bigint[] literal so the planner sees
        // concrete values instead of an opaque parameter or function call.
        final StringJoiner joiner = new StringJoiner(",", "{", "}");
        for (final Long teamId : teamIds) {
            joiner.add(String.valueOf(teamId));
        }
        final String teamIdsLiteralSql = "cast('" + joiner + "' as bigint[])";

        final String sql = /* language=SQL */ """
                EXISTS (\
                SELECT 1 \
                FROM "PROJECT_ACCESS_TEAMS" pat \
                INNER JOIN "PROJECT_HIERARCHY" ph \
                ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID" \
                WHERE pat."TEAM_ID" = ANY (%s) \
                AND ph."CHILD_PROJECT_ID" = %s\
                )""".formatted(teamIdsLiteralSql, objectExpr.toSQLText().toSQL());

        // Let DN know when we interpreted parameters as literal.
        if (objectExpr.isParameter() && objectExpr instanceof final SQLLiteral sqlLiteral) {
            stmt.getQueryGenerator().useParameterExpressionAsLiteral(sqlLiteral);
        }
        if (arrayLiteralArg.isParameter()) {
            stmt.getQueryGenerator().useParameterExpressionAsLiteral(arrayLiteralArg);
        }

        return new BooleanExpression(stmt, booleanTypeMapping, sql);
    }

    private SQLExpression getUserExpression(
            SQLStatement stmt,
            ObjectExpression objectExpr,
            IntegerLiteral userIdArg) {
        if (!(userIdArg.getValue() instanceof final Long userId)) {
            throw new IllegalArgumentException(
                    "Expected user ID argument to be of type %s, but got %s".formatted(
                            Long.class.getName(),
                            userIdArg.getValue().getClass().getName()));
        }

        final JavaTypeMapping booleanTypeMapping = stmt.getSQLExpressionFactory().getMappingForType(Boolean.class);

        final String sql = /* language=SQL */ """
                EXISTS (\
                SELECT 1 \
                FROM "PROJECT_ACCESS_USERS" pau \
                INNER JOIN "PROJECT_HIERARCHY" ph \
                ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID" \
                WHERE ph."CHILD_PROJECT_ID" = %s \
                AND pau."USER_ID" = %d\
                )""".formatted(objectExpr.toSQLText().toSQL(), userId);

        // Let DN know when we interpreted parameters as literal.
        if (objectExpr.isParameter() && objectExpr instanceof final SQLLiteral sqlLiteral) {
            stmt.getQueryGenerator().useParameterExpressionAsLiteral(sqlLiteral);
        }
        if (userIdArg.isParameter()) {
            stmt.getQueryGenerator().useParameterExpressionAsLiteral(userIdArg);
        }

        return new BooleanExpression(stmt, booleanTypeMapping, sql);
    }

}
