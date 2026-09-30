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
package org.dependencytrack.auth.workloadidentity;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.persistence.jdbi.PaginationConfig;
import org.jdbi.v3.core.mapper.Nested;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/// @since 5.2.0
public interface WorkloadIdentityBindingDao extends SqlObject {

    @SqlUpdate("""
        INSERT INTO "WORKLOAD_IDENTITY_BINDING" (
          "ID"
        , "PROVIDER_NAME"
        , "USER_ID"
        , "SUBJECT"
        , "CONDITION"
        )
        SELECT :id
             , wip."NAME"
             , usr."ID"
             , :subject
             , :condition
          FROM "WORKLOAD_IDENTITY_PROVIDER" AS wip
         INNER JOIN "USER" AS usr
            ON usr."TYPE" = 'SERVICE'
           AND usr."USERNAME" = :username
         WHERE wip."NAME" = :providerName
        """)
    boolean create(
            @Bind UUID id,
            @Bind String providerName,
            @Bind String username,
            @Bind String subject,
            @Bind @Nullable String condition);

    @SqlUpdate("""
        DELETE
          FROM "WORKLOAD_IDENTITY_BINDING" AS wib
         USING "USER" AS usr
         WHERE usr."ID" = wib."USER_ID"
           AND usr."TYPE" = 'SERVICE'
           AND usr."USERNAME" = :username
           AND wib."ID" = :id
        """)
    boolean delete(@Bind String username, @Bind UUID id);

    @SqlQuery("""
        SELECT EXISTS(
          SELECT 1
            FROM "USER"
           WHERE "TYPE" = 'SERVICE'
             AND "USERNAME" = :username
        )
        """)
    boolean existsServiceAccount(@Bind String username);

    record MatchingBindingRow(
            UUID id,
            long userId,
            String username,
            boolean suspended,
            String subject,
            @Nullable String condition) {}

    @SqlQuery("""
        SELECT wib."ID"
             , usr."ID" AS user_id
             , usr."USERNAME"
             , usr."SUSPENDED"
             , wib."SUBJECT"
             , wib."CONDITION"
          FROM "WORKLOAD_IDENTITY_BINDING" AS wib
         INNER JOIN "USER" AS usr
            ON usr."ID" = wib."USER_ID"
         WHERE wib."PROVIDER_NAME" = :providerName
           AND usr."TYPE" = 'SERVICE'
           AND usr."USERNAME" = :username
           AND (
                 wib."SUBJECT" = :subject
                 OR (
                   RIGHT(wib."SUBJECT", 1) = '*'
                   AND STARTS_WITH(CAST(:subject AS TEXT), LEFT(wib."SUBJECT", -1))
                 )
               )
         ORDER BY wib."ID"
        """)
    @RegisterConstructorMapper(MatchingBindingRow.class)
    List<MatchingBindingRow> findMatchingBindings(
            @Bind String providerName, @Bind String username, @Bind String subject);

    @SqlUpdate("""
        UPDATE "WORKLOAD_IDENTITY_BINDING"
           SET "LAST_USED_AT" = NOW()
         WHERE "ID" = :id
           AND ("LAST_USED_AT" IS NULL OR "LAST_USED_AT" < NOW())
        """)
    void updateLastUsedAt(@Bind UUID id);

    record WorkloadIdentityBindingRow(
            UUID id,
            String providerName,
            String subject,
            @Nullable String condition,
            Instant createdAt,
            @Nullable Instant lastUsedAt) {}

    record ListWorkloadIdentityBindingsPageToken(
            String lastProviderName, String lastSubject, UUID lastId, TotalCount totalCount) implements PageToken {}

    record ListWorkloadIdentityBindingsRow(@Nested WorkloadIdentityBindingRow binding, long totalCount) {}

    default Page<WorkloadIdentityBindingRow> listBindings(String username, int limit, @Nullable String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListWorkloadIdentityBindingsPageToken.class);

        final List<ListWorkloadIdentityBindingsRow> rows = getHandle()
                .createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="lastProviderName" type="boolean" -->
                    SELECT wib."ID"
                         , wib."PROVIDER_NAME"
                         , wib."SUBJECT"
                         , wib."CONDITION"
                         , wib."CREATED_AT"
                         , wib."LAST_USED_AT"
                         , COUNT(*) OVER () AS total_count
                      FROM "WORKLOAD_IDENTITY_BINDING" AS wib
                     INNER JOIN "USER" AS usr
                        ON usr."ID" = wib."USER_ID"
                     WHERE usr."TYPE" = 'SERVICE'
                       AND usr."USERNAME" = :username
                    <#if lastProviderName>
                       AND (wib."PROVIDER_NAME", wib."SUBJECT", wib."ID") > (:lastProviderName, :lastSubject, :lastId)
                    </#if>
                     ORDER BY wib."PROVIDER_NAME"
                            , wib."SUBJECT"
                            , wib."ID"
                     LIMIT (:limit + 1)
                    """)
                .bind("username", username)
                .bind("lastProviderName", decodedPageToken != null ? decodedPageToken.lastProviderName() : null)
                .bind("lastSubject", decodedPageToken != null ? decodedPageToken.lastSubject() : null)
                .bind("lastId", decodedPageToken != null ? decodedPageToken.lastId() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(ConstructorMapper.of(ListWorkloadIdentityBindingsRow.class))
                .list();

        final TotalCount totalCount = decodedPageToken != null
                ? decodedPageToken.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);

        final List<WorkloadIdentityBindingRow> pageRows = rows.stream()
                .limit(limit)
                .map(ListWorkloadIdentityBindingsRow::binding)
                .toList();
        final ListWorkloadIdentityBindingsPageToken nextPageToken = rows.size() > limit
                ? new ListWorkloadIdentityBindingsPageToken(
                        pageRows.getLast().providerName(),
                        pageRows.getLast().subject(),
                        pageRows.getLast().id(),
                        totalCount)
                : null;

        return new Page<>(pageRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }
}
