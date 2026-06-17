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

import org.dependencytrack.model.Epss;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.SqlObject;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @since 5.0.0
 */
public interface EpssDao extends SqlObject {

    default int createOrUpdateAll(final Collection<Epss> epssRecords) {
        final Update update = getHandle().createUpdate("""
                INSERT INTO "EPSS" ("CVE", "SCORE", "PERCENTILE")
                SELECT * FROM UNNEST(:cves, :scores, :percentiles)
                ON CONFLICT ("CVE") DO UPDATE
                SET "SCORE" = EXCLUDED."SCORE"
                  , "PERCENTILE" = EXCLUDED."PERCENTILE"
                WHERE "EPSS"."SCORE" IS DISTINCT FROM EXCLUDED."SCORE"
                   OR "EPSS"."PERCENTILE" IS DISTINCT FROM EXCLUDED."PERCENTILE"
                """);

        final var cves = new ArrayList<String>(epssRecords.size());
        final var scores = new ArrayList<BigDecimal>(epssRecords.size());
        final var percentiles = new ArrayList<BigDecimal>(epssRecords.size());

        for (final Epss epssRecord : epssRecords) {
            cves.add(epssRecord.getCve());
            scores.add(epssRecord.getScore());
            percentiles.add(epssRecord.getPercentile());
        }

        return update
                .registerArrayType(BigDecimal.class, "numeric")
                .bindArray("cves", String.class, cves)
                .bindArray("scores", BigDecimal.class, scores)
                .bindArray("percentiles", BigDecimal.class, percentiles)
                .execute();
    }

}
