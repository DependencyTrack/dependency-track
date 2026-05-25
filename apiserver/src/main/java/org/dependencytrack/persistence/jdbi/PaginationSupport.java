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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.common.pagination.Page.TotalCount;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
@NullMarked
public interface PaginationSupport extends SqlObject {

    /// @see [#getBoundedTotalCount(String, Map, Integer, String)]
    default TotalCount getBoundedTotalCountWithProjectAcl(
            String fromWhereClause,
            @Nullable Map<String, Object> whereParams,
            @Nullable Integer threshold,
            String projectIdColumn) {
        requireNonNull(projectIdColumn, "projectIdColumn must not be null");
        return getBoundedTotalCount(fromWhereClause, whereParams, threshold, projectIdColumn);
    }

    /// Calculates the total count of rows that match a given `FROM ... WHERE` clause.
    ///
    /// For queries that may match a large number of rows, to the point where Postgres struggles
    /// to count them, pass a non-`null` `threshold` to cap the count.
    /// If the total is equal to or lower than `threshold`, the returned count will be of type
    /// [TotalCount.Type#EXACT], otherwise [TotalCount.Type#AT_LEAST].
    ///
    /// For queries that are naturally bounded (e.g. scoped to a single project),
    /// pass `null` as `threshold` to perform an unbounded exact count.
    ///
    /// For queries that
    ///
    ///   - are expected to match only a small number of rows, or
    ///   - are expected to be executed very rarely
    ///
    /// consider simply adding a `COUNT(*) OVER() AS total_count`
    /// window function to your `SELECT` statement.
    ///
    /// For queries that use keyset pagination, note that the pagination
    /// condition (e.g. `"NAME" > :lastName`) **must not** be included in
    /// `fromWhereClause`, as it reduces the result set and thus would cause
    /// counts to fluctuate (i.e. reduce) across pages.
    ///
    /// @param fromWhereClause The `FROM ... WHERE ...` clause to use.
    ///                        May contain parameter placeholders such as `:foo`.
    /// @param whereParams     Parameter values to apply to the `WHERE` clause.
    /// @param threshold       The threshold up to which rows will be counted, or `null`
    ///                        for an unbounded exact count.
    /// @return The total count of rows.
    /// @see [Postgres slow counting](https://wiki.postgresql.org/wiki/Slow_Counting)
    default TotalCount getBoundedTotalCount(
            String fromWhereClause,
            @Nullable Map<String, Object> whereParams,
            @Nullable Integer threshold,
            @Nullable String projectIdColumn) {
        requireNonNull(fromWhereClause, "fromWhereClause must not be null");
        if (threshold != null && threshold < 1) {
            throw new IllegalArgumentException("threshold must not be less than 1");
        }
        if (projectIdColumn != null && projectIdColumn.isEmpty()) {
            throw new IllegalArgumentException("ACL column must not be blank");
        }

        final boolean includeAcl = projectIdColumn != null;

        // NB: The limit is only effective when used on a subquery.
        // SELECT COUNT(*) ... LIMIT X is *not* sufficient:
        // https://pganalyze.com/blog/5mins-postgres-limited-count
        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
                <#-- @ftlvariable name="fromWhereClause" type="String" -->
                <#-- @ftlvariable name="includeAcl" type="boolean" -->
                <#-- @ftlvariable name="threshold" type="boolean" -->
                <#if threshold>
                SELECT COUNT(*)
                  FROM (
                    SELECT 1
                      ${fromWhereClause}
                <#if includeAcl>
                       AND ${apiProjectAclCondition}
                </#if>
                     LIMIT (:threshold + 1)
                  ) AS t
                <#else>
                SELECT COUNT(*)
                  ${fromWhereClause}
                <#if includeAcl>
                   AND ${apiProjectAclCondition}
                </#if>
                </#if>
                """);

        if (includeAcl) {
            query.addCustomizer(new DefineApiProjectAclCondition.StatementCustomizer(
                    JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                    projectIdColumn));
        }

        final long count = query
                .bindMap(whereParams)
                .bind("threshold", threshold)
                .define("fromWhereClause", fromWhereClause)
                .define("includeAcl", includeAcl)
                .defineNamedBindings()
                .mapTo(long.class)
                .one();

        if (threshold == null) {
            return new TotalCount(count, TotalCount.Type.EXACT);
        }

        return new TotalCount(
                Math.min(count, threshold),
                count > threshold
                        ? TotalCount.Type.AT_LEAST
                        : TotalCount.Type.EXACT);
    }

}
