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
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/// SAML groups, and their mappings to teams.
///
/// @since 5.3.0
public interface SamlGroupDao extends SqlObject {

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

    record SamlGroupRow(UUID uuid, String name, @Json List<SamlTeamRef> teams) {}

    record ListGroupsPageToken(String lastName, TotalCount totalCount) implements PageToken {}

    record ListGroupsRow(UUID uuid, String name, @Json List<SamlTeamRef> teams, long totalCount) {}

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
}
