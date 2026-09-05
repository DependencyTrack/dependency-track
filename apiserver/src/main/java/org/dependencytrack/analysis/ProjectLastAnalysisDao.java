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
package org.dependencytrack.analysis;

import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/// @since 5.1.0
public interface ProjectLastAnalysisDao {

    @SqlQuery("""
            SELECT p."ID" AS "id"
                 , p."UUID" AS "uuid"
              FROM "PROJECT_LAST_ANALYSIS" AS pla
             INNER JOIN "PROJECT" AS p
                ON p."ID" = pla."PROJECT_ID"
             WHERE pla."ATTEMPTED_AT" < :dueBefore
             ORDER BY pla."ATTEMPTED_AT"
                    , pla."PROJECT_ID"
             LIMIT :limit
            """)
    @RegisterConstructorMapper(ProjectDueForAnalysis.class)
    List<ProjectDueForAnalysis> getProjectsDue(@Bind Instant dueBefore, @Bind int limit);

    @SqlUpdate("""
            UPDATE "PROJECT_LAST_ANALYSIS"
               SET "ATTEMPTED_AT" = GREATEST("ATTEMPTED_AT", :attemptedAt)
             WHERE "PROJECT_ID" = ANY(:projectIds)
            """)
    int recordAttempt(@Bind long[] projectIds, @Bind Instant attemptedAt);

    @SqlUpdate("""
            UPDATE "PROJECT_LAST_ANALYSIS"
               SET "ATTEMPTED_AT" = GREATEST("ATTEMPTED_AT", :attemptedAt)
             WHERE "PROJECT_ID" = (
               SELECT p."ID"
                 FROM "PROJECT" AS p
                WHERE p."UUID" = :projectUuid
             )
            """)
    int recordAttempt(@Bind UUID projectUuid, @Bind Instant attemptedAt);
}
