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

import org.dependencytrack.model.PackageMetadataResolutionStatus;
import org.jdbi.v3.core.Handle;

import java.util.Map;

/// @since 5.1.0
public final class PackageMetadataResolutionDao {

    private final Handle jdbiHandle;

    public PackageMetadataResolutionDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public int upsertAll(Map<String, PackageMetadataResolutionStatus> statusByPurl) {
        if (statusByPurl.isEmpty()) {
            return 0;
        }

        final var purls = new String[statusByPurl.size()];
        final var statuses = new String[statusByPurl.size()];

        int i = 0;
        for (final var entry : statusByPurl.entrySet()) {
            purls[i] = entry.getKey();
            statuses[i] = entry.getValue().name();
            i++;
        }

        return jdbiHandle
                .createUpdate(/* language=SQL */ """
                        INSERT INTO "PACKAGE_METADATA_RESOLUTION" (
                          "PURL"
                        , "STATUS"
                        , "LAST_ATTEMPTED_AT"
                        )
                        SELECT *
                             , NOW()
                          FROM UNNEST(:purls, :statuses)
                         ORDER BY 1
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "STATUS" = EXCLUDED."STATUS"
                          , "LAST_ATTEMPTED_AT" = EXCLUDED."LAST_ATTEMPTED_AT"
                        """)
                .bind("purls", purls)
                .bind("statuses", statuses)
                .execute();
    }

}
