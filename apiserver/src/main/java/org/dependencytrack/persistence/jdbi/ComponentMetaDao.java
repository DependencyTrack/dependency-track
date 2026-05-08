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

import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @since 5.0.0
 */
public interface ComponentMetaDao extends SqlObject {

    record ComponentMetaInfoRecord(
            UUID componentUuid,
            String purl,
            Instant lastFetch,
            Instant publishedAt,
            IntegrityMatchStatus integrityCheckStatus,
            String repositoryUrl) {
    }

    default Map<UUID, ComponentMetaInformation> getComponentMetaInfo(final Collection<UUID> uuids) {
        final Query query = getHandle().createQuery("""
                SELECT c."UUID" AS component_uuid
                     , c."PURL"
                     , pam."RESOLVED_AT" AS last_fetch
                     , pam."PUBLISHED_AT"
                     , CASE
                         WHEN c."SHA_256" IS NOT NULL AND pam."HASH_SHA256" IS NOT NULL
                         THEN CASE
                                WHEN LOWER(c."SHA_256") = LOWER(pam."HASH_SHA256")
                                THEN 'HASH_MATCH_PASSED'
                                ELSE 'HASH_MATCH_FAILED'
                              END
                         WHEN c."SHA_512" IS NOT NULL AND pam."HASH_SHA512" IS NOT NULL
                         THEN CASE
                                WHEN LOWER(c."SHA_512") = LOWER(pam."HASH_SHA512")
                                THEN 'HASH_MATCH_PASSED'
                                ELSE 'HASH_MATCH_FAILED'
                              END
                         WHEN c."SHA1" IS NOT NULL AND pam."HASH_SHA1" IS NOT NULL
                         THEN CASE
                                WHEN LOWER(c."SHA1") = LOWER(pam."HASH_SHA1")
                                THEN 'HASH_MATCH_PASSED'
                                ELSE 'HASH_MATCH_FAILED'
                              END
                         WHEN c."MD5" IS NOT NULL AND pam."HASH_MD5" IS NOT NULL
                         THEN CASE
                                WHEN LOWER(c."MD5") = LOWER(pam."HASH_MD5")
                                THEN 'HASH_MATCH_PASSED'
                                ELSE 'HASH_MATCH_FAILED'
                              END
                         WHEN c."SHA_256" IS NULL AND c."SHA_512" IS NULL AND c."SHA1" IS NULL AND c."MD5" IS NULL
                         THEN 'COMPONENT_MISSING_HASH'
                         ELSE 'HASH_MATCH_UNKNOWN'
                       END AS "INTEGRITY_CHECK_STATUS"
                     , pam."RESOLVED_FROM" AS repository_url
                  FROM "COMPONENT" AS c
                 INNER JOIN "PACKAGE_ARTIFACT_METADATA" AS pam
                    ON c."PURL" = pam."PURL"
                 WHERE c."UUID" = ANY(:uuids)
                """);

        return query
                .bindArray("uuids", UUID.class, uuids)
                .map(ConstructorMapper.of(ComponentMetaInfoRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        ComponentMetaInfoRecord::componentUuid,
                        record -> new ComponentMetaInformation(
                                record.publishedAt() != null ? Date.from(record.publishedAt()) : null,
                                record.integrityCheckStatus(),
                                record.lastFetch() != null ? Date.from(record.lastFetch()) : null,
                                record.repositoryUrl())));
    }

    default ComponentMetaInformation getComponentMetaInfo(final UUID uuid) {
        final Map<UUID, ComponentMetaInformation> metaByUuid = getComponentMetaInfo(List.of(uuid));
        return metaByUuid.get(uuid);
    }

}
