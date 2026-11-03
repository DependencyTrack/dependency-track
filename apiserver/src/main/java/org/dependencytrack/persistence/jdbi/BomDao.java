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

import org.jdbi.v3.sqlobject.SingleValue;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface BomDao {

    @SqlQuery("""
            SELECT "BOM"."ORIGINAL_FILE_METADATA"
              FROM "BOM"
             INNER JOIN "PROJECT"
                ON "PROJECT"."ID" = "BOM"."PROJECT_ID"
             WHERE "PROJECT"."UUID" = :projectUuid
               AND "BOM"."ORIGINAL_FILE_METADATA" IS NOT NULL
             ORDER BY "BOM"."IMPORTED" DESC, "BOM"."ID" DESC
             LIMIT 1
            """)
    @SingleValue
    byte @Nullable [] getLatestOriginalFileMetadata(@Bind UUID projectUuid);

    @SqlQuery("""
            SELECT EXISTS(
                     SELECT 1
                       FROM "BOM"
                      INNER JOIN "PROJECT"
                        ON "PROJECT"."ID" = "BOM"."PROJECT_ID"
                      WHERE "PROJECT"."UUID" = :projectUuid
                        AND "BOM"."ORIGINAL_FILE_METADATA" = :fileMetadata
                 )
            """)
    boolean isOriginalFileReferenced(@Bind UUID projectUuid, @Bind byte[] fileMetadata);

    @SqlQuery("""
           UPDATE "BOM" AS bom
              SET "ORIGINAL_FILE_METADATA" = NULL
             FROM (
                SELECT older."ID"
                     , older."ORIGINAL_FILE_METADATA"
                     , "PROJECT"."UUID" AS "PROJECT_UUID"
                  FROM "BOM" AS boundary
                 INNER JOIN "BOM" AS older
                    ON older."PROJECT_ID" = boundary."PROJECT_ID"
                 INNER JOIN "PROJECT"
                    ON "PROJECT"."ID" = boundary."PROJECT_ID"
                 WHERE boundary."ID" = :boundaryBomId
                   AND older."ID" < boundary."ID"
                   AND older."ORIGINAL_FILE_METADATA" IS NOT NULL
                   AND older."ORIGINAL_FILE_METADATA" IS DISTINCT FROM boundary."ORIGINAL_FILE_METADATA"
                 FOR UPDATE OF older
            ) AS old
           WHERE bom."ID" = old."ID"
          RETURNING old."PROJECT_UUID"
                  , old."ORIGINAL_FILE_METADATA"
          """)
    @RegisterConstructorMapper(ProjectDao.OriginalBomFileMetadataRow.class)
    List<ProjectDao.OriginalBomFileMetadataRow> clearOlderOriginalFileMetadata(@Bind long boundaryBomId);

    @SqlQuery("""
            UPDATE "BOM" AS bom
               SET "ORIGINAL_FILE_METADATA" = NULL
              FROM (
                SELECT expired."ID"
                     , expired."ORIGINAL_FILE_METADATA"
                     , "PROJECT"."UUID" AS "PROJECT_UUID"
                  FROM "BOM" AS expired
                 INNER JOIN "PROJECT"
                    ON "PROJECT"."ID" = expired."PROJECT_ID"
                 WHERE expired."ORIGINAL_FILE_METADATA" IS NOT NULL
                   AND expired."IMPORTED" <= :cutoff
                   AND NOT EXISTS (
                         SELECT 1
                           FROM "BOM" AS retained
                          WHERE retained."PROJECT_ID" = expired."PROJECT_ID"
                            AND retained."IMPORTED" > :cutoff
                            AND retained."ORIGINAL_FILE_METADATA" = expired."ORIGINAL_FILE_METADATA"
                       )
                 ORDER BY expired."ID"
                 LIMIT :batchSize
                   FOR UPDATE OF expired
              ) AS old
             WHERE bom."ID" = old."ID"
            RETURNING old."PROJECT_UUID"
                    , old."ORIGINAL_FILE_METADATA"
            """)
    @RegisterConstructorMapper(ProjectDao.OriginalBomFileMetadataRow.class)
    List<ProjectDao.OriginalBomFileMetadataRow> clearExpiredOriginalFileMetadata(
            @Bind Instant cutoff, @Bind int batchSize);
}
