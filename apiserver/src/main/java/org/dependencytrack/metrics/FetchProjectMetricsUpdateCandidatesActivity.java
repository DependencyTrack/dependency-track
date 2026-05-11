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
package org.dependencytrack.metrics;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.proto.internal.workflow.v1.FetchProjectMetricsUpdateCandidatesRes;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "fetch-projects-for-metrics-update", defaultTaskQueue = "metrics-updates")
public final class FetchProjectMetricsUpdateCandidatesActivity implements Activity<Void, FetchProjectMetricsUpdateCandidatesRes> {

    private static final int BATCH_SIZE = 100;

    @Override
    public @Nullable FetchProjectMetricsUpdateCandidatesRes execute(ActivityContext ctx, @Nullable Void argument) {
        final List<UUID> projectUuids = withJdbiHandle(
                handle -> handle
                        .createQuery("""
                                SELECT "UUID"
                                  FROM "PROJECT"
                                 WHERE "INACTIVE_SINCE" IS NULL
                                   AND "COLLECTION_LOGIC" IS NULL
                                   AND NOT EXISTS(
                                     SELECT 1
                                       FROM "PROJECTMETRICS"
                                      WHERE "PROJECT_ID" = "PROJECT"."ID"
                                        AND "LAST_OCCURRENCE" >= CURRENT_DATE
                                        AND "LAST_OCCURRENCE" < CURRENT_DATE + INTERVAL '1 day'
                                   )
                                 ORDER BY "ID"
                                 LIMIT :batchSize
                                """)
                        .bind("batchSize", BATCH_SIZE)
                        .mapTo(UUID.class)
                        .list());

        if (projectUuids.isEmpty()) {
            return null;
        }

        return FetchProjectMetricsUpdateCandidatesRes.newBuilder()
                .addAllProjectUuids(projectUuids.stream().map(UUID::toString).toList())
                .build();
    }

}
