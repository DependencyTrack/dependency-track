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
package org.dependencytrack.epss;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

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
            cves.add(epssRecord.cve());
            scores.add(epssRecord.score());
            percentiles.add(epssRecord.percentile());
        }

        return update.registerArrayType(BigDecimal.class, "numeric")
                .bindArray("cves", String.class, cves)
                .bindArray("scores", BigDecimal.class, scores)
                .bindArray("percentiles", BigDecimal.class, percentiles)
                .execute();
    }

    @SqlQuery(/* language=SQL */ """
            SELECT "CVE"
                 , "SCORE"
                 , "PERCENTILE"
              FROM (
                SELECT ee."CVE"
                     , ee."SCORE"
                     , ee."PERCENTILE"
                  FROM "EPSS" AS ee
                 WHERE :vulnSource = 'NVD'
                   AND ee."CVE" = :vulnId
                UNION ALL
                SELECT ee."CVE"
                     , ee."SCORE"
                     , ee."PERCENTILE"
                  FROM "VULNERABILITY_ALIAS" AS va
                 INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                    ON cve_a."GROUP_ID" = va."GROUP_ID"
                   AND cve_a."SOURCE" = 'NVD'
                 INNER JOIN "EPSS" AS ee
                    ON ee."CVE" = cve_a."VULN_ID"
                 WHERE :vulnSource != 'NVD'
                   AND va."SOURCE" = :vulnSource
                   AND va."VULN_ID" = :vulnId
              ) candidates
             ORDER BY "SCORE" DESC NULLS LAST
                    , "PERCENTILE" DESC NULLS LAST
                    , "CVE"
             LIMIT 1
            """)
    @RegisterConstructorMapper(Epss.class)
    @Nullable
    Epss getEffectiveEpssForVuln(@Bind String vulnSource, @Bind String vulnId);

    default Map<VulnerabilityKey, Epss> getEffectiveEpssForVulns(Collection<VulnerabilityKey> keys) {
        if (keys.isEmpty()) {
            return Map.of();
        }

        final var vulnSources = new ArrayList<String>(keys.size());
        final var vulnIds = new ArrayList<String>(keys.size());
        for (final VulnerabilityKey key : keys) {
            vulnSources.add(key.source().name());
            vulnIds.add(key.vulnId());
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                        SELECT t."VULN_SOURCE"
                             , t."VULN_ID"
                             , best."CVE"
                             , best."SCORE"
                             , best."PERCENTILE"
                          FROM UNNEST(:vulnSources, :vulnIds)
                            AS t("VULN_SOURCE", "VULN_ID")
                          LEFT JOIN LATERAL (
                            SELECT "CVE"
                                 , "SCORE"
                                 , "PERCENTILE"
                              FROM (
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "EPSS" AS ee
                                 WHERE t."VULN_SOURCE" = 'NVD'
                                   AND ee."CVE" = t."VULN_ID"
                                UNION ALL
                                SELECT ee."CVE"
                                     , ee."SCORE"
                                     , ee."PERCENTILE"
                                  FROM "VULNERABILITY_ALIAS" AS va
                                 INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                                    ON cve_a."GROUP_ID" = va."GROUP_ID"
                                   AND cve_a."SOURCE" = 'NVD'
                                 INNER JOIN "EPSS" AS ee
                                    ON ee."CVE" = cve_a."VULN_ID"
                                 WHERE t."VULN_SOURCE" != 'NVD'
                                   AND va."SOURCE" = t."VULN_SOURCE"
                                   AND va."VULN_ID" = t."VULN_ID"
                              ) candidates
                             ORDER BY "SCORE" DESC NULLS LAST
                                    , "PERCENTILE" DESC NULLS LAST
                                    , "CVE"
                             LIMIT 1
                          ) AS best ON TRUE
                         WHERE best."CVE" IS NOT NULL
                        """)
                .bindArray("vulnSources", String.class, vulnSources)
                .bindArray("vulnIds", String.class, vulnIds)
                .reduceRows(new HashMap<>(), (result, row) -> {
                    result.put(
                            new VulnerabilityKey(
                                    row.getColumn("VULN_ID", String.class),
                                    Vulnerability.Source.valueOf(row.getColumn("VULN_SOURCE", String.class))),
                            new Epss(
                                    row.getColumn("CVE", String.class),
                                    row.getColumn("SCORE", BigDecimal.class),
                                    row.getColumn("PERCENTILE", BigDecimal.class)));
                    return result;
                });
    }
}
