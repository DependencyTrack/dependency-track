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

    /**
     * Calculates the bounded total count of rows that match a given {@code FROM ... WHERE} clause.
     * <p>
     * Should be used for queries that may match a large number of rows,
     * to the point where Postgres struggles to count them.
     * <p>
     * For queries that
     * <ul>
     *     <li>are expected to match only a small number of rows, or</li>
     *     <li>are expected to be executed very rarely, or</li>
     *     <li>or are expected to be executed very rarely</li>
     * </ul>
     * consider simply adding a {@code COUNT(*) OVER() AS total_count}
     * window function to your {@code SELECT} statement.
     * <p>
     * For queries that use keyset pagination, note that the pagination
     * condition (e.g., {@code "NAME" > :lastName}) <strong>must not</strong>
     * be included in {@code fromWhereClause}, as it reduces the result set
     * and thus would cause counts to fluctuate (i.e., reduce) across pages.
     *
     * @param fromWhereClause The {@code FROM ... WHERE ...} clause to use.
     *                        May contain parameter placeholders such as {@code :foo}.
     * @param whereParams     Parameter values to apply to the {@code WHERE} clause.
     * @param threshold       The threshold up to which rows will be counted. If the total count
     *                        is equal to or lower than this value, the returned count will be
     *                        of type {@link TotalCount.Type#EXACT}, otherwise it will be
     *                        {@link TotalCount.Type#AT_LEAST}.
     * @return The total count of rows.
     * @see <a href="https://wiki.postgresql.org/wiki/Slow_Counting">Postgres slow counting</a>
     */
    default TotalCount getBoundedTotalCount(
            String fromWhereClause,
            @Nullable Map<String, Object> whereParams,
            int threshold) {
        return getBoundedTotalCount(fromWhereClause, whereParams, threshold, null);
    }

    /**
     * Calculates a bounded total count while applying the API project ACL condition using the provided project ID column.
     * The {@code fromWhereClause} must already contain a {@code WHERE} clause; this method simply appends
     * {@code AND ${apiProjectAclCondition}} to it.
     */
    default TotalCount getBoundedTotalCountWithProjectAcl(
            String fromWhereClause,
            @Nullable Map<String, Object> whereParams,
            int threshold,
            String projectIdColumn) {
        requireNonNull(projectIdColumn, "projectIdColumn must not be null");
        return getBoundedTotalCount(fromWhereClause, whereParams, threshold, projectIdColumn);
    }

    private TotalCount getBoundedTotalCount(
            String fromWhereClause,
            @Nullable Map<String, Object> whereParams,
            int threshold,
            @Nullable String projectIdColumn) {
        requireNonNull(fromWhereClause, "fromWhereClause must not be null");
        if (threshold < 1) {
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
                <#-- @ftlvariable name="fromWhereClause" type="String" -->
                <#-- @ftlvariable name="threshold" type="boolean" -->
                <#-- @ftlvariable name="includeAcl" type="boolean" -->
                SELECT COUNT(*)
                  FROM (
                    SELECT 1
                      ${fromWhereClause}
                <#if includeAcl>
                       AND ${apiProjectAclCondition}
                </#if>
                     LIMIT (:threshold + 1)
                  ) AS t
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

        return new TotalCount(
                Math.min(count, threshold),
                count > threshold
                        ? TotalCount.Type.AT_LEAST
                        : TotalCount.Type.EXACT);
    }

}
