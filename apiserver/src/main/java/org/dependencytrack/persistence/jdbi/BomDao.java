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
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.Nullable;

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
    @Nullable
    byte[] getLatestOriginalFileMetadata(@Bind UUID projectUuid);
}
