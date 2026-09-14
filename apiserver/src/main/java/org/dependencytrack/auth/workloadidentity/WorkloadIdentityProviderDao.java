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

import static org.dependencytrack.util.PersistenceUtil.escapeLikePattern;

/// @since 5.2.0
public interface WorkloadIdentityProviderDao extends SqlObject {

    record WorkloadIdentityProviderRow(
            String name,
            WorkloadIdentityProvider.Type type,
            String issuer,
            String audience,
            @Nullable String jwksUrl,
            @Nullable List<String> jwksKeyIds,
            int sessionLifetimeSeconds,
            Instant createdAt) {}

    @SqlQuery("""
        SELECT "NAME"
             , "TYPE"
             , "ISSUER"
             , "AUDIENCE"
             , "JWKS_URL"
             , CASE
                 WHEN "JWKS" IS NULL THEN NULL
                 ELSE ARRAY(
                   SELECT key ->> 'kid'
                     FROM JSONB_ARRAY_ELEMENTS("JWKS" -> 'keys') AS key
                    WHERE key -> 'kid' IS NOT NULL
                 )
               END AS jwks_key_ids
             , "SESSION_LIFETIME_SECONDS"
             , "CREATED_AT"
          FROM "WORKLOAD_IDENTITY_PROVIDER"
         WHERE "NAME" = :name
        """)
    @RegisterConstructorMapper(WorkloadIdentityProviderRow.class)
    @Nullable
    WorkloadIdentityProviderRow getByName(@Bind String name);

    record ExchangeProviderRow(@Nested WorkloadIdentityProvider provider, int sessionLifetimeSeconds) {}

    @SqlQuery("""
        SELECT "TYPE"
             , "ISSUER"
             , "AUDIENCE"
             , "JWKS_URL"
             , CAST("JWKS" AS TEXT) AS jwks
             , "SESSION_LIFETIME_SECONDS"
          FROM "WORKLOAD_IDENTITY_PROVIDER"
         WHERE "NAME" = :name
        """)
    @RegisterConstructorMapper(ExchangeProviderRow.class)
    @Nullable
    ExchangeProviderRow getExchangeProviderByName(@Bind String name);

    @SqlUpdate("""
        INSERT INTO "WORKLOAD_IDENTITY_PROVIDER" (
          "NAME"
        , "TYPE"
        , "ISSUER"
        , "AUDIENCE"
        , "JWKS_URL"
        , "JWKS"
        , "SESSION_LIFETIME_SECONDS"
        )
        VALUES (
          :name
        , :type
        , :issuer
        , :audience
        , :jwksUrl
        , CAST(:jwks AS JSONB)
        , :sessionLifetimeSeconds
        )
        """)
    void create(
            @Bind String name,
            @Bind WorkloadIdentityProvider.Type type,
            @Bind String issuer,
            @Bind String audience,
            @Bind @Nullable String jwksUrl,
            @Bind @Nullable String jwks,
            @Bind int sessionLifetimeSeconds);

    @SqlUpdate("""
        UPDATE "WORKLOAD_IDENTITY_PROVIDER"
           SET "ISSUER" = COALESCE(CAST(:issuer AS TEXT), "ISSUER")
             , "AUDIENCE" = COALESCE(CAST(:audience AS TEXT), "AUDIENCE")
             , "JWKS" = CASE
                          WHEN CAST(:jwks AS TEXT) IS NOT NULL THEN CAST(:jwks AS JSONB)
                          WHEN CAST(:jwksUrl AS TEXT) IS NOT NULL THEN NULL
                          ELSE "JWKS"
                        END
             , "JWKS_URL" = CASE
                              WHEN CAST(:jwksUrl AS TEXT) IS NOT NULL THEN :jwksUrl
                              WHEN CAST(:jwks AS TEXT) IS NOT NULL THEN NULL
                              ELSE "JWKS_URL"
                            END
             , "SESSION_LIFETIME_SECONDS" = COALESCE(CAST(:sessionLifetimeSeconds AS INT), "SESSION_LIFETIME_SECONDS")
             , "UPDATED_AT" = NOW()
         WHERE "NAME" = :name
        """)
    boolean update(
            @Bind String name,
            @Bind @Nullable String issuer,
            @Bind @Nullable String audience,
            @Bind @Nullable String jwksUrl,
            @Bind @Nullable String jwks,
            @Bind @Nullable Integer sessionLifetimeSeconds);

    @SqlUpdate("""
        DELETE
          FROM "WORKLOAD_IDENTITY_PROVIDER"
         WHERE "NAME" = :name
        """)
    boolean delete(@Bind String name);

    record ListWorkloadIdentityProvidersPageToken(String lastName, TotalCount totalCount) implements PageToken {}

    record ListWorkloadIdentityProvidersRow(@Nested WorkloadIdentityProviderRow provider, long totalCount) {}

    default Page<WorkloadIdentityProviderRow> listProviders(
            int limit, @Nullable String pageToken, @Nullable String nameFilter) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListWorkloadIdentityProvidersPageToken.class);

        final List<ListWorkloadIdentityProvidersRow> rows = getHandle()
                .createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="lastName" type="boolean" -->
                    <#-- @ftlvariable name="namePattern" type="boolean" -->
                    SELECT "NAME"
                         , "TYPE"
                         , "ISSUER"
                         , "AUDIENCE"
                         , "JWKS_URL"
                         , CASE
                             WHEN "JWKS" IS NULL THEN NULL
                             ELSE ARRAY(
                               SELECT key ->> 'kid'
                                 FROM JSONB_ARRAY_ELEMENTS("JWKS" -> 'keys') AS key
                                WHERE key -> 'kid' IS NOT NULL
                             )
                           END AS jwks_key_ids
                         , "SESSION_LIFETIME_SECONDS"
                         , "CREATED_AT"
                         , COUNT(*) OVER () AS total_count
                      FROM "WORKLOAD_IDENTITY_PROVIDER"
                     WHERE TRUE
                    <#if namePattern>
                       AND "NAME" ILIKE :namePattern ESCAPE '!'
                    </#if>
                    <#if lastName>
                       AND "NAME" > :lastName
                    </#if>
                     ORDER BY "NAME"
                     LIMIT (:limit + 1)
                    """)
                .bind("namePattern", nameFilter != null ? "%" + escapeLikePattern(nameFilter) + "%" : null)
                .bind("lastName", decodedPageToken != null ? decodedPageToken.lastName() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(ConstructorMapper.of(ListWorkloadIdentityProvidersRow.class))
                .list();

        final TotalCount totalCount = decodedPageToken != null
                ? decodedPageToken.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);

        final List<WorkloadIdentityProviderRow> pageRows = rows.stream()
                .limit(limit)
                .map(ListWorkloadIdentityProvidersRow::provider)
                .toList();
        final ListWorkloadIdentityProvidersPageToken nextPageToken = rows.size() > limit
                ? new ListWorkloadIdentityProvidersPageToken(pageRows.getLast().name(), totalCount)
                : null;

        return new Page<>(pageRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }
}
