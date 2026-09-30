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

import alpine.model.ServiceAccount;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.util.PersistenceUtil.escapeLikePattern;

/// @since 5.2.0
@NullMarked
public interface ServiceAccountDao extends SqlObject {

    record ServiceAccountRow(String username, @Nullable String email, boolean suspended) {}

    record ServiceAccountDetailsRow(
            String username,
            @Nullable String email,
            boolean suspended,
            @Json List<Team> teams,
            List<String> permissions) {

        public record Team(UUID uuid, String name) {}
    }

    @SqlQuery("""
        SELECT u."USERNAME"
             , u."EMAIL"
             , u."SUSPENDED"
             , (
                 SELECT COALESCE(
                          JSONB_AGG(JSONB_BUILD_OBJECT('uuid', t."UUID", 'name', t."NAME") ORDER BY t."NAME")
                        , CAST('[]' AS JSONB)
                        )
                   FROM "USERS_TEAMS" AS ut
                  INNER JOIN "TEAM" AS t
                     ON t."ID" = ut."TEAM_ID"
                  WHERE ut."USER_ID" = u."ID"
               ) AS teams
             , (
                 SELECT COALESCE(ARRAY_AGG(p."NAME" ORDER BY p."NAME"), '{}')
                   FROM "USERS_PERMISSIONS" AS up
                  INNER JOIN "PERMISSION" AS p
                     ON p."ID" = up."PERMISSION_ID"
                  WHERE up."USER_ID" = u."ID"
               ) AS permissions
          FROM "USER" AS u
         WHERE u."TYPE" = 'SERVICE'
           AND u."USERNAME" = :username
        """)
    @RegisterConstructorMapper(ServiceAccountDetailsRow.class)
    @Nullable
    ServiceAccountDetailsRow getByUsername(@Bind String username);

    @SqlUpdate("""
        INSERT INTO "USER" ("TYPE", "USERNAME", "EMAIL", "SUSPENDED")
        VALUES ('SERVICE', :username, NULLIF(:email, ''), FALSE)
        """)
    void create(@Bind String username, @Bind @Nullable String email);

    record UpdatedServiceAccountRow(boolean suspendedChanged, boolean emailChanged) {}

    @SqlUpdate("""
        UPDATE "USER" AS new
           SET "EMAIL" = CASE
                           WHEN CAST(:email AS TEXT) IS NULL THEN new."EMAIL"
                           ELSE NULLIF(:email, '')
                         END
             , "SUSPENDED" = COALESCE(CAST(:suspended AS BOOLEAN), new."SUSPENDED")
          FROM (
            SELECT "ID"
                 , "EMAIL"
                 , "SUSPENDED"
              FROM "USER"
             WHERE "TYPE" = 'SERVICE'
               AND "USERNAME" = :username
               FOR UPDATE
          ) AS old
         WHERE new."ID" = old."ID"
        RETURNING new."SUSPENDED" IS DISTINCT FROM old."SUSPENDED" AS suspended_changed
                , new."EMAIL" IS DISTINCT FROM old."EMAIL" AS email_changed
        """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(UpdatedServiceAccountRow.class)
    @Nullable
    UpdatedServiceAccountRow update(
            @Bind String username, @Bind @Nullable String email, @Bind @Nullable Boolean suspended);

    @SqlUpdate("""
        DELETE
          FROM "USER"
         WHERE "TYPE" = 'SERVICE'
           AND "USERNAME" = :username
        """)
    int delete(@Bind String username);

    record ListServiceAccountsPageToken(String lastUsername, TotalCount totalCount) implements PageToken {}

    record ListServiceAccountsRow(String username, @Nullable String email, boolean suspended, long totalCount) {}

    default Page<ServiceAccountRow> listServiceAccounts(
            int limit, @Nullable String pageToken, @Nullable String nameFilter) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListServiceAccountsPageToken.class);

        final List<ListServiceAccountsRow> rows = getHandle()
                .createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="lastUsername" type="boolean" -->
                    <#-- @ftlvariable name="usernamePattern" type="boolean" -->
                    SELECT "USERNAME"
                         , "EMAIL"
                         , "SUSPENDED"
                         , COUNT(*) OVER () AS total_count
                      FROM "USER"
                     WHERE "TYPE" = 'SERVICE'
                    <#if usernamePattern>
                       AND "USERNAME" ILIKE :usernamePattern ESCAPE '!'
                    </#if>
                    <#if lastUsername>
                       AND "USERNAME" > :lastUsername
                    </#if>
                     ORDER BY "USERNAME"
                     LIMIT (:limit + 1)
                    """)
                .bind(
                        "usernamePattern",
                        nameFilter != null
                                ? ServiceAccount.USERNAME_PREFIX + "%" + escapeLikePattern(nameFilter) + "%"
                                : null)
                .bind("lastUsername", decodedPageToken != null ? decodedPageToken.lastUsername() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(ConstructorMapper.of(ListServiceAccountsRow.class))
                .list();

        final TotalCount totalCount = decodedPageToken != null
                ? decodedPageToken.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);

        final List<ServiceAccountRow> pageRows = rows.stream()
                .limit(limit)
                .map(row -> new ServiceAccountRow(row.username(), row.email(), row.suspended()))
                .toList();
        final ListServiceAccountsPageToken nextPageToken = rows.size() > limit
                ? new ListServiceAccountsPageToken(pageRows.getLast().username(), totalCount)
                : null;

        return new Page<>(pageRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }
}
