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
package org.dependencytrack.vulnanalysis;

import org.dependencytrack.model.FindingKey;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;

final class FindingDao {

    private final Handle handle;

    FindingDao(Handle handle) {
        this.handle = handle;
    }

    List<FindingAttribution> getExistingAttributions(long projectId) {
        return handle
                .createQuery("""
                        SELECT fa."ID"
                             , fa."COMPONENT_ID"
                             , fa."VULNERABILITY_ID"
                             , fa."ANALYZERIDENTITY"
                          FROM "FINDINGATTRIBUTION" AS fa
                         WHERE fa."PROJECT_ID" = :projectId
                           AND fa."DELETED_AT" IS NULL
                        """)
                .bind("projectId", projectId)
                .map((rs, ctx) -> new FindingAttribution(
                        rs.getLong("ID"),
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID"),
                        rs.getString("ANALYZERIDENTITY")))
                .list();
    }

    List<FindingKey> createFindings(Collection<FindingKey> findings) {
        if (findings.isEmpty()) {
            return List.of();
        }

        final var componentIds = new long[findings.size()];
        final var vulnIds = new long[findings.size()];

        int i = 0;
        for (final FindingKey finding : findings) {
            componentIds[i] = finding.componentId();
            vulnIds[i] = finding.vulnDbId();
            i++;
        }

        return handle
                .createUpdate("""
                        INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
                        SELECT *
                          FROM UNNEST(:componentIds, :vulnIds)
                            AS t(component_id, vuln_id)
                         ORDER BY component_id
                                , vuln_id
                        ON CONFLICT DO NOTHING
                        RETURNING "COMPONENT_ID"
                                , "VULNERABILITY_ID"
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnIds", vulnIds)
                .executeAndReturnGeneratedKeys()
                .map((rs, ctx) -> new FindingKey(
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID")))
                .list();
    }

    int createAttributions(Collection<CreateAttributionCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var vulnIds = new long[commands.size()];
        final var componentIds = new long[commands.size()];
        final var projectIds = new long[commands.size()];
        final var analyzerIdentities = new String[commands.size()];
        final var referenceUrls = new String[commands.size()];

        int i = 0;
        for (final CreateAttributionCommand command : commands) {
            vulnIds[i] = command.vulnDbId();
            componentIds[i] = command.componentId();
            projectIds[i] = command.projectId();
            analyzerIdentities[i] = command.analyzerName();
            referenceUrls[i] = command.referenceUrl();
            i++;
        }

        return handle
                .createUpdate("""
                        INSERT INTO "FINDINGATTRIBUTION" AS fa (
                          "VULNERABILITY_ID"
                        , "COMPONENT_ID"
                        , "PROJECT_ID"
                        , "ANALYZERIDENTITY"
                        , "ATTRIBUTED_ON"
                        , "REFERENCE_URL"
                        )
                        SELECT vuln_id
                             , component_id
                             , project_id
                             , analyzer_identity
                             , NOW()
                             , reference_url
                          FROM UNNEST(:vulnIds, :componentIds, :projectIds, :analyzerIdentities, :referenceUrls)
                            AS t(vuln_id, component_id, project_id, analyzer_identity, reference_url)
                         ORDER BY vuln_id
                                , component_id
                                , analyzer_identity
                        ON CONFLICT ("VULNERABILITY_ID", "COMPONENT_ID", "ANALYZERIDENTITY") DO UPDATE
                        SET "ATTRIBUTED_ON" = EXCLUDED."ATTRIBUTED_ON"
                          , "DELETED_AT" = NULL
                          , "REFERENCE_URL" = EXCLUDED."REFERENCE_URL"
                        WHERE fa."DELETED_AT" IS NOT NULL
                        """)
                .bind("vulnIds", vulnIds)
                .bind("componentIds", componentIds)
                .bind("projectIds", projectIds)
                .bind("analyzerIdentities", analyzerIdentities)
                .bind("referenceUrls", referenceUrls)
                .execute();
    }

    int deleteAttributions(Collection<Long> attributionIds) {
        if (attributionIds.isEmpty()) {
            return 0;
        }

        return handle
                .createUpdate("""
                        UPDATE "FINDINGATTRIBUTION"
                           SET "DELETED_AT" = NOW()
                         WHERE "ID" = ANY(:ids)
                           AND "DELETED_AT" IS NULL
                        """)
                .bind("ids", attributionIds.toArray(Long[]::new))
                .execute();
    }

    record FindingAttribution(
            long id,
            long componentId,
            long vulnDbId,
            String analyzerName) {
    }

    record CreateAttributionCommand(
            long vulnDbId,
            long componentId,
            long projectId,
            String analyzerName,
            @Nullable String referenceUrl) {
    }

}
