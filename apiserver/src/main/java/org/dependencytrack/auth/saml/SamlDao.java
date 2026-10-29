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
package org.dependencytrack.auth.saml;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.persistence.jdbi.PaginationConfig;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.util.PersistenceUtil.escapeLikePattern;

/// @since 5.3.0
public interface SamlDao extends SqlObject {

    // Login flow.

    @SqlUpdate("""
        INSERT INTO "SAML_AUTHN_REQUEST" ("ID", "CODE_CHALLENGE", "REDIRECT_PATH", "EXPIRES_AT")
        VALUES (:id, :codeChallenge, :redirectPath, :expiresAt)
        """)
    void createAuthnRequest(
            @Bind String id, @Bind String codeChallenge, @Bind @Nullable String redirectPath, @Bind Instant expiresAt);

    record PendingAuthnRequest(
            String codeChallenge, @Nullable String redirectPath, Instant expiresAt) {}

    /// Deletes a pending authentication request, so that it cannot be answered twice.
    @SqlUpdate("""
        DELETE
          FROM "SAML_AUTHN_REQUEST"
         WHERE "ID" = :id
        RETURNING "CODE_CHALLENGE", "REDIRECT_PATH", "EXPIRES_AT"
        """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(PendingAuthnRequest.class)
    @Nullable
    PendingAuthnRequest consumeAuthnRequest(@Bind String id);

    @SqlUpdate("""
        INSERT INTO "SAML_LOGIN_CODE" ("CODE_HASH", "USER_ID", "CODE_CHALLENGE", "EXPIRES_AT")
        VALUES (:codeHash, :userId, :codeChallenge, :expiresAt)
        """)
    void createLoginCode(@Bind String codeHash, @Bind long userId, @Bind String codeChallenge, @Bind Instant expiresAt);

    record LoginCode(long userId, String codeChallenge, Instant expiresAt) {}

    /// Deletes a login code, so that it cannot be used twice.
    @SqlUpdate("""
        DELETE
          FROM "SAML_LOGIN_CODE"
         WHERE "CODE_HASH" = :codeHash
        RETURNING "USER_ID", "CODE_CHALLENGE", "EXPIRES_AT"
        """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(LoginCode.class)
    @Nullable
    LoginCode consumeLoginCode(@Bind String codeHash);

    @SqlUpdate("""
        DELETE FROM "SAML_AUTHN_REQUEST" WHERE "EXPIRES_AT" < NOW()
        """)
    int deleteExpiredAuthnRequests();

    @SqlUpdate("""
        DELETE FROM "SAML_LOGIN_CODE" WHERE "EXPIRES_AT" < NOW()
        """)
    int deleteExpiredLoginCodes();

    // Users.

    record UserRow(long id, String type, @Nullable String email) {}

    @SqlQuery("""
        SELECT "ID", "TYPE", "EMAIL"
          FROM "USER"
         WHERE "USERNAME" = :username
        """)
    @RegisterConstructorMapper(UserRow.class)
    @Nullable
    UserRow getUser(@Bind String username);

    @SqlUpdate("""
        INSERT INTO "USER" ("TYPE", "USERNAME", "EMAIL")
        VALUES ('SAML', :username, :email)
        RETURNING "ID"
        """)
    @GetGeneratedKeys
    long createUser(@Bind String username, @Bind @Nullable String email);

    @SqlUpdate("""
        UPDATE "USER"
           SET "EMAIL" = :email
         WHERE "ID" = :id
           AND "EMAIL" IS DISTINCT FROM :email
        """)
    void updateEmail(@Bind long id, @Bind @Nullable String email);

    @SqlUpdate("""
        DELETE
          FROM "USER"
         WHERE "TYPE" = 'SAML'
           AND "USERNAME" = :username
        """)
    int deleteUser(@Bind String username);

    /// Creates all groups that do not exist yet.
    ///
    /// @return Names of the groups that were created.
    default List<String> createGroups(Collection<String> names) {
        if (names.isEmpty()) {
            return List.of();
        }

        // Consistent insertion order prevents deadlocks between concurrent logins.
        final List<String> sortedNames = names.stream().distinct().sorted().toList();
        return getHandle()
                .createQuery("""
                    INSERT INTO "SAML_GROUP" ("NAME")
                    SELECT name
                      FROM UNNEST(:names) AS name
                    ON CONFLICT ("NAME") DO NOTHING
                    RETURNING "NAME"
                    """)
                .bindArray("names", String.class, sortedNames)
                .mapTo(String.class)
                .list();
    }

    /// Makes the user a member of exactly those teams that are mapped to one of the given groups.
    default void synchronizeTeams(long userId, Collection<String> groupNames) {
        getHandle()
                .createUpdate("""
                    WITH cte_mapped_team AS (
                      SELECT DISTINCT m."TEAM_ID"
                        FROM "SAML_GROUP" AS g
                       INNER JOIN "SAML_GROUP_MAPPING" AS m
                          ON m."GROUP_ID" = g."ID"
                       WHERE g."NAME" = ANY(:groupNames)
                    ),
                    cte_removed AS (
                      DELETE
                        FROM "USERS_TEAMS"
                       WHERE "USER_ID" = :userId
                         AND "TEAM_ID" NOT IN (SELECT "TEAM_ID" FROM cte_mapped_team)
                    )
                    INSERT INTO "USERS_TEAMS" ("USER_ID", "TEAM_ID")
                    SELECT :userId, "TEAM_ID"
                      FROM cte_mapped_team
                    ON CONFLICT DO NOTHING
                    """)
                .bind("userId", userId)
                .bindArray("groupNames", String.class, List.copyOf(groupNames))
                .execute();
    }

    default void addToTeams(long userId, Collection<String> teamNames) {
        if (teamNames.isEmpty()) {
            return;
        }

        getHandle()
                .createUpdate("""
                    INSERT INTO "USERS_TEAMS" ("USER_ID", "TEAM_ID")
                    SELECT :userId, "ID"
                      FROM "TEAM"
                     WHERE "NAME" = ANY(:teamNames)
                    ON CONFLICT DO NOTHING
                    """)
                .bind("userId", userId)
                .bindArray("teamNames", String.class, List.copyOf(teamNames))
                .execute();
    }

    // Administration.

    record TeamRef(String uuid, String name) {}

    record SamlGroupRow(UUID uuid, String name, @Json List<TeamRef> teams) {}

    record ListGroupsPageToken(String lastName, TotalCount totalCount) implements PageToken {}

    record ListGroupsRow(UUID uuid, String name, @Json List<TeamRef> teams, long totalCount) {}

    default Page<SamlGroupRow> listGroups(int limit, @Nullable String pageToken, @Nullable String teamUuid) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListGroupsPageToken.class);

        final List<ListGroupsRow> rows = getHandle()
                .createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="lastName" type="boolean" -->
                    <#-- @ftlvariable name="teamUuid" type="boolean" -->
                    SELECT g."UUID"
                         , g."NAME"
                         , (
                             SELECT COALESCE(
                                      JSONB_AGG(JSONB_BUILD_OBJECT('uuid', t."UUID", 'name', t."NAME") ORDER BY t."NAME")
                                    , CAST('[]' AS JSONB)
                                    )
                               FROM "SAML_GROUP_MAPPING" AS m
                              INNER JOIN "TEAM" AS t
                                 ON t."ID" = m."TEAM_ID"
                              WHERE m."GROUP_ID" = g."ID"
                           ) AS teams
                         , COUNT(*) OVER () AS total_count
                      FROM "SAML_GROUP" AS g
                     WHERE TRUE
                    <#if teamUuid>
                       AND EXISTS (
                             SELECT 1
                               FROM "SAML_GROUP_MAPPING" AS m
                              INNER JOIN "TEAM" AS t
                                 ON t."ID" = m."TEAM_ID"
                              WHERE m."GROUP_ID" = g."ID"
                                AND t."UUID" = :teamUuid
                           )
                    </#if>
                    <#if lastName>
                       AND g."NAME" > :lastName
                    </#if>
                     ORDER BY g."NAME"
                     LIMIT (:limit + 1)
                    """)
                .bind("teamUuid", teamUuid)
                .bind("lastName", decodedPageToken != null ? decodedPageToken.lastName() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(ConstructorMapper.of(ListGroupsRow.class))
                .list();

        final TotalCount totalCount = decodedPageToken != null
                ? decodedPageToken.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);

        final List<SamlGroupRow> pageRows = rows.stream()
                .limit(limit)
                .map(row -> new SamlGroupRow(row.uuid(), row.name(), row.teams()))
                .toList();
        final ListGroupsPageToken nextPageToken =
                rows.size() > limit ? new ListGroupsPageToken(pageRows.getLast().name(), totalCount) : null;

        return new Page<>(pageRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    @SqlUpdate("""
        INSERT INTO "SAML_GROUP" ("NAME")
        VALUES (:name)
        RETURNING "UUID"
        """)
    @GetGeneratedKeys
    UUID createGroup(@Bind String name);

    @SqlUpdate("""
        DELETE FROM "SAML_GROUP" WHERE "UUID" = :uuid
        """)
    int deleteGroup(@Bind UUID uuid);

    @SqlQuery("""
        SELECT EXISTS(SELECT 1 FROM "SAML_GROUP" WHERE "UUID" = :groupUuid)
           AND EXISTS(SELECT 1 FROM "TEAM" WHERE "UUID" = :teamUuid)
        """)
    boolean groupAndTeamExist(@Bind UUID groupUuid, @Bind String teamUuid);

    @SqlUpdate("""
        INSERT INTO "SAML_GROUP_MAPPING" ("GROUP_ID", "TEAM_ID")
        SELECT g."ID", t."ID"
          FROM "SAML_GROUP" AS g
         CROSS JOIN "TEAM" AS t
         WHERE g."UUID" = :groupUuid
           AND t."UUID" = :teamUuid
        ON CONFLICT DO NOTHING
        """)
    int createMapping(@Bind UUID groupUuid, @Bind String teamUuid);

    @SqlUpdate("""
        DELETE
          FROM "SAML_GROUP_MAPPING" AS m
         USING "SAML_GROUP" AS g
             , "TEAM" AS t
         WHERE g."ID" = m."GROUP_ID"
           AND t."ID" = m."TEAM_ID"
           AND g."UUID" = :groupUuid
           AND t."UUID" = :teamUuid
        """)
    int deleteMapping(@Bind UUID groupUuid, @Bind String teamUuid);

    record SamlUserRow(
            String username, @Nullable String email, @Json List<TeamRef> teams, List<String> permissions) {}

    record ListUsersPageToken(String lastUsername, TotalCount totalCount) implements PageToken {}

    record ListUsersRow(
            String username,
            @Nullable String email,
            @Json List<TeamRef> teams,
            List<String> permissions,
            long totalCount) {}

    default Page<SamlUserRow> listUsers(int limit, @Nullable String pageToken, @Nullable String usernameFilter) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListUsersPageToken.class);

        final List<ListUsersRow> rows = getHandle()
                .createQuery(/* language=InjectedFreeMarker */ """
                    <#-- @ftlvariable name="lastUsername" type="boolean" -->
                    <#-- @ftlvariable name="usernamePattern" type="boolean" -->
                    SELECT u."USERNAME"
                         , u."EMAIL"
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
                         , COUNT(*) OVER () AS total_count
                      FROM "USER" AS u
                     WHERE u."TYPE" = 'SAML'
                    <#if usernamePattern>
                       AND u."USERNAME" ILIKE :usernamePattern ESCAPE '!'
                    </#if>
                    <#if lastUsername>
                       AND u."USERNAME" > :lastUsername
                    </#if>
                     ORDER BY u."USERNAME"
                     LIMIT (:limit + 1)
                    """)
                .bind("usernamePattern", usernameFilter != null ? "%" + escapeLikePattern(usernameFilter) + "%" : null)
                .bind("lastUsername", decodedPageToken != null ? decodedPageToken.lastUsername() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(ConstructorMapper.of(ListUsersRow.class))
                .list();

        final TotalCount totalCount = decodedPageToken != null
                ? decodedPageToken.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);

        final List<SamlUserRow> pageRows = rows.stream()
                .limit(limit)
                .map(row -> new SamlUserRow(row.username(), row.email(), row.teams(), row.permissions()))
                .toList();
        final ListUsersPageToken nextPageToken =
                rows.size() > limit ? new ListUsersPageToken(pageRows.getLast().username(), totalCount) : null;

        return new Page<>(pageRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }
}
