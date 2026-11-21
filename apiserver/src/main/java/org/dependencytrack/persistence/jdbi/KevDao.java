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

import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/// @since 5.1.0
public interface KevDao extends SqlObject {

    default void upsertBatch(String asserter, Collection<KevAssertion> batch) {
        final var assertionByVulnKey = new LinkedHashMap<VulnerabilityKey, KevAssertion>(batch.size());
        for (final KevAssertion assertion : batch) {
            assertionByVulnKey.put(new VulnerabilityKey(assertion.vulnId(), assertion.vulnSource()), assertion);
        }
        if (assertionByVulnKey.isEmpty()) {
            return;
        }

        final var vulnSources = new String[assertionByVulnKey.size()];
        final var vulnIds = new String[assertionByVulnKey.size()];
        final var publishedAts = new Instant[assertionByVulnKey.size()];
        final var requiredActions = new String[assertionByVulnKey.size()];
        final var knownRansomwares = new Boolean[assertionByVulnKey.size()];
        final var descriptions = new String[assertionByVulnKey.size()];
        final var raws = new String[assertionByVulnKey.size()];

        int i = 0;
        for (final KevAssertion record : assertionByVulnKey.values()) {
            vulnSources[i] = record.vulnSource();
            vulnIds[i] = record.vulnId();
            publishedAts[i] = record.publishedAt();
            requiredActions[i] = record.requiredAction();
            knownRansomwares[i] = record.knownRansomware();
            descriptions[i] = record.description();
            raws[i] = record.raw() != null ? record.raw().toString() : null;
            i++;
        }

        final Update update = getHandle().createUpdate("""
                INSERT INTO "KEV_ASSERTION" (
                  "ASSERTER"
                , "VULN_SOURCE"
                , "VULN_ID"
                , "PUBLISHED_AT"
                , "REQUIRED_ACTION"
                , "KNOWN_RANSOMWARE"
                , "DESCRIPTION"
                , "RAW"
                )
                SELECT :asserter
                     , t.source
                     , t.vuln_id
                     , t.published_at
                     , t.required_actions
                     , t.known_ransomware
                     , t.description
                     , CAST(t.raw AS JSONB)
                  FROM UNNEST(
                    :vulnSources
                  , :vulnIds
                  , :publishedAts
                  , :requiredActions
                  , :knownRansomwares
                  , :descriptions
                  , :raws
                  ) AS t(
                    source
                  , vuln_id
                  , published_at
                  , required_actions
                  , known_ransomware
                  , description
                  , raw
                  )
                ON CONFLICT ("ASSERTER", "VULN_SOURCE", "VULN_ID") DO UPDATE
                SET "PUBLISHED_AT" = EXCLUDED."PUBLISHED_AT"
                  , "REQUIRED_ACTION" = EXCLUDED."REQUIRED_ACTION"
                  , "KNOWN_RANSOMWARE" = EXCLUDED."KNOWN_RANSOMWARE"
                  , "DESCRIPTION" = EXCLUDED."DESCRIPTION"
                  , "RAW" = EXCLUDED."RAW"
                  , "UPDATED_AT" = now()
                WHERE "KEV_ASSERTION"."PUBLISHED_AT" IS DISTINCT FROM EXCLUDED."PUBLISHED_AT"
                   OR "KEV_ASSERTION"."REQUIRED_ACTION" IS DISTINCT FROM EXCLUDED."REQUIRED_ACTION"
                   OR "KEV_ASSERTION"."KNOWN_RANSOMWARE" IS DISTINCT FROM EXCLUDED."KNOWN_RANSOMWARE"
                   OR "KEV_ASSERTION"."DESCRIPTION" IS DISTINCT FROM EXCLUDED."DESCRIPTION"
                   OR "KEV_ASSERTION"."RAW" IS DISTINCT FROM EXCLUDED."RAW"
                """);

        update.registerArrayType(Instant.class, "timestamptz")
                .registerArrayType(Boolean.class, "bool")
                .bind("asserter", asserter)
                .bind("vulnSources", vulnSources)
                .bind("vulnIds", vulnIds)
                .bind("publishedAts", publishedAts)
                .bind("requiredActions", requiredActions)
                .bind("knownRansomwares", knownRansomwares)
                .bind("descriptions", descriptions)
                .bind("raws", raws)
                .execute();
    }

    default void deleteStale(String asserter, Collection<VulnerabilityKey> vulnKeys) {
        final var vulnSources = new String[vulnKeys.size()];
        final var vulnIds = new String[vulnKeys.size()];

        int i = 0;
        for (final VulnerabilityKey vulnKey : vulnKeys) {
            vulnSources[i] = vulnKey.source().name();
            vulnIds[i] = vulnKey.vulnId();
            i++;
        }

        getHandle()
                .createUpdate("""
                        DELETE FROM "KEV_ASSERTION"
                         WHERE "ASSERTER" = :asserter
                           AND NOT EXISTS (
                             SELECT 1
                               FROM UNNEST(:vulnSources, :vulnIds)
                                 AS t(source, vuln_id)
                              WHERE t.source = "KEV_ASSERTION"."VULN_SOURCE"
                                AND t.vuln_id = "KEV_ASSERTION"."VULN_ID"
                         )
                        """)
                .bind("asserter", asserter)
                .bind("vulnSources", vulnSources)
                .bind("vulnIds", vulnIds)
                .execute();
    }

    @SqlQuery("""
            SELECT "ASSERTER"
                 , "VULN_SOURCE"
                 , "VULN_ID"
                 , "PUBLISHED_AT"
                 , "REQUIRED_ACTION"
                 , "KNOWN_RANSOMWARE"
                 , "DESCRIPTION"
                 , "CREATED_AT"
                 , "UPDATED_AT"
              FROM "KEV_ASSERTION"
             WHERE ("VULN_SOURCE", "VULN_ID") IN (<@sql.vulnAliasGroup vulnSource=':source' vulnId=':vulnId'/>)
             ORDER BY "VULN_SOURCE", "VULN_ID", "ASSERTER"
            """)
    @RegisterConstructorMapper(KevAssertionRow.class)
    List<KevAssertionRow> getAssertions(@Bind String source, @Bind String vulnId);

    default Map<VulnerabilityKey, List<KevAssertionRow>> getAssertions(Collection<VulnerabilityKey> vulnKeys) {
        if (vulnKeys.isEmpty()) {
            return Map.of();
        }

        final var uniqueKeys = new LinkedHashSet<>(vulnKeys);
        final var vulnSources = new String[uniqueKeys.size()];
        final var vulnIds = new String[uniqueKeys.size()];

        int i = 0;
        for (final VulnerabilityKey vulnKey : uniqueKeys) {
            vulnSources[i] = vulnKey.source().name();
            vulnIds[i] = vulnKey.vulnId();
            i++;
        }

        final var rows = getHandle()
                .createQuery("""
                        WITH requested AS (
                          SELECT t.source AS requested_source
                               , t.vuln_id AS requested_vuln_id
                            FROM UNNEST(:vulnSources, :vulnIds) AS t(source, vuln_id)
                        )
                        , alias_matches AS (
                          SELECT requested_source
                               , requested_vuln_id
                               , requested_source AS source
                               , requested_vuln_id AS vuln_id
                            FROM requested
                          UNION
                          SELECT requested.requested_source
                               , requested.requested_vuln_id
                               , alias_sibling."SOURCE"
                               , alias_sibling."VULN_ID"
                            FROM requested
                           INNER JOIN "VULNERABILITY_ALIAS" AS alias_self
                              ON alias_self."SOURCE" = requested.requested_source
                             AND alias_self."VULN_ID" = requested.requested_vuln_id
                           INNER JOIN "VULNERABILITY_ALIAS" AS alias_sibling
                              ON alias_sibling."GROUP_ID" = alias_self."GROUP_ID"
                        )
                        SELECT alias_matches.requested_source
                             , alias_matches.requested_vuln_id
                             , ka."ASSERTER"
                             , ka."VULN_SOURCE"
                             , ka."VULN_ID"
                             , ka."PUBLISHED_AT"
                             , ka."REQUIRED_ACTION"
                             , ka."KNOWN_RANSOMWARE"
                             , ka."DESCRIPTION"
                             , ka."CREATED_AT"
                             , ka."UPDATED_AT"
                          FROM alias_matches
                         INNER JOIN "KEV_ASSERTION" AS ka
                            ON ka."VULN_SOURCE" = alias_matches.source
                           AND ka."VULN_ID" = alias_matches.vuln_id
                         ORDER BY alias_matches.requested_source
                                , alias_matches.requested_vuln_id
                                , ka."ASSERTER"
                        """)
                .bind("vulnSources", vulnSources)
                .bind("vulnIds", vulnIds)
                .map((rs, ctx) -> {
                    final OffsetDateTime publishedAt = rs.getObject("PUBLISHED_AT", OffsetDateTime.class);
                    final OffsetDateTime createdAt = rs.getObject("CREATED_AT", OffsetDateTime.class);
                    final OffsetDateTime updatedAt = rs.getObject("UPDATED_AT", OffsetDateTime.class);

                    return Map.entry(
                            new VulnerabilityKey(
                                    rs.getString("requested_vuln_id"),
                                    Vulnerability.Source.valueOf(rs.getString("requested_source"))),
                            new KevAssertionRow(
                                    rs.getString("ASSERTER"),
                                    rs.getString("VULN_SOURCE"),
                                    rs.getString("VULN_ID"),
                                    publishedAt != null ? publishedAt.toInstant() : null,
                                    rs.getString("REQUIRED_ACTION"),
                                    rs.getObject("KNOWN_RANSOMWARE", Boolean.class),
                                    rs.getString("DESCRIPTION"),
                                    createdAt != null ? createdAt.toInstant() : null,
                                    updatedAt != null ? updatedAt.toInstant() : null));
                })
                .list();

        final var assertionsByVulnKey = new LinkedHashMap<VulnerabilityKey, List<KevAssertionRow>>();
        for (final var row : rows) {
            assertionsByVulnKey
                    .computeIfAbsent(row.getKey(), ignored -> new ArrayList<>())
                    .add(row.getValue());
        }

        return assertionsByVulnKey;
    }

    record KevAssertionRow(
            String asserter,
            String vulnSource,
            String vulnId,
            @Nullable Instant publishedAt,
            @Nullable String requiredAction,
            @Nullable Boolean knownRansomware,
            @Nullable String description,
            Instant createdAt,
            Instant updatedAt) {}

    default boolean hasAssertions(String asserter) {
        return getHandle()
                .createQuery("""
                        SELECT EXISTS (
                          SELECT 1
                            FROM "KEV_ASSERTION"
                           WHERE "ASSERTER" = :asserter
                        )
                        """)
                .bind("asserter", asserter)
                .mapTo(boolean.class)
                .one();
    }
}
