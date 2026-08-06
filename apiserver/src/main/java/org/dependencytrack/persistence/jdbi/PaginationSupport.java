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

import alpine.persistence.Pagination;
import alpine.resources.AlpineRequest;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

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

        if (projectIdColumn != null) {
            // Only install the secondary ACL customizer when the chosen column
            // differs from the default. Otherwise the existing condition defined
            // by ApiRequestStatementCustomizer is already correct and no rewrite is needed.
            final String defaultProjectIdColumn =
                    getHandle().getConfig(ApiRequestConfig.class).projectAclProjectIdColumn();
            if (!projectIdColumn.equals(defaultProjectIdColumn)) {
                query.addCustomizer(new DefineApiProjectAclCondition.StatementCustomizer(
                        JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION, projectIdColumn));
            }
        }

        // NB: The count query inherits bindings from the handle's customizer chain
        // (e.g. pagination offset / limit) and from the threshold bind even when the
        // template doesn't reference them.
        query.getConfig(SqlStatements.class).setUnusedBindingAllowed(true);

        final long count = query.bindMap(whereParams)
                .bind("threshold", threshold)
                .define("fromWhereClause", fromWhereClause)
                .define("includeAcl", projectIdColumn != null)
                .defineNamedBindings()
                .mapTo(long.class)
                .one();

        if (threshold == null) {
            return new TotalCount(count, TotalCount.Type.EXACT);
        }

        return TotalCount.bounded(count, threshold);
    }

    /// Resolves the exact total count from a page with a window count,
    /// or falls back to a separate count query when the page carries none.
    ///
    /// @since 5.1.0
    default <T> TotalCount exactTotalCount(
            List<T> items, Function<T, @Nullable Long> windowTotalCountExtractor, LongSupplier exactCountSupplier) {
        if (items.isEmpty()) {
            // When the page is empty, we could erroneously report a total count of 0,
            // even if there were preceding pages. If this was a request for a later
            // page, we have to run a separate count query to find the true total.
            return new TotalCount(itemsPrecedingPage() > 0 ? exactCountSupplier.getAsLong() : 0, TotalCount.Type.EXACT);
        }

        return new TotalCount(
                requireNonNull(
                        windowTotalCountExtractor.apply(items.getFirst()),
                        "totalCount must not be null when the window count was requested"),
                TotalCount.Type.EXACT);
    }

    /// Interprets a count capped at `threshold`, never below what the page itself proves.
    ///
    /// The count query only runs when it can still improve on [#pageDerivedTotalCount(int)].
    /// Otherwise its result would be discarded.
    ///
    /// @since 5.1.0
    default TotalCount boundedTotalCountOrAtLeast(LongSupplier boundedCountSupplier, int threshold, int returnedItems) {
        final TotalCount pageDerived = pageDerivedTotalCount(returnedItems);
        if (pageDerived.type() == TotalCount.Type.EXACT || pageDerived.value() > threshold) {
            return pageDerived;
        }

        return TotalCount.bounded(boundedCountSupplier.getAsLong(), threshold);
    }

    /// The best total provable from the page alone,
    /// for queries where even a capped count is too expensive.
    ///
    /// Only works for offset pagination, **do not use for token pagination**.
    ///
    /// @since 5.1.0
    default TotalCount pageDerivedTotalCount(int returnedItems) {
        final Pagination pagination = apiPagination();
        if (pagination == null) {
            // Without pagination, we know the query returned the entire result set.
            return new TotalCount(returnedItems, TotalCount.Type.EXACT);
        }

        if (returnedItems == 0) {
            // An empty page doesn't tell us whether truly no items exist,
            // or we just moved past the number of items in the collection.
            return new TotalCount(0, pagination.getOffset() == 0 ? TotalCount.Type.EXACT : TotalCount.Type.AT_LEAST);
        }

        return new TotalCount(
                pagination.getOffset() + returnedItems,
                returnedItems < pagination.getLimit() ? TotalCount.Type.EXACT : TotalCount.Type.AT_LEAST);
    }

    private long itemsPrecedingPage() {
        final Pagination pagination = apiPagination();
        return pagination != null ? pagination.getOffset() : 0;
    }

    private @Nullable Pagination apiPagination() {
        final AlpineRequest apiRequest =
                getHandle().getConfig(ApiRequestConfig.class).apiRequest();
        if (apiRequest == null) {
            return null;
        }

        final Pagination pagination = apiRequest.getPagination();
        return pagination != null && pagination.isPaginated() ? pagination : null;
    }

    default <T> T withJitDisabled(Supplier<T> supplier) {
        return getHandle().inTransaction(trx -> {
            trx.createUpdate("SET LOCAL jit = OFF")
                    // The handle may carry bindings from ApiRequestStatementCustomizer
                    // (e.g. pagination offset / limit) that this statement doesn't consume.
                    .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                    .execute();
            return supplier.get();
        });
    }
}
