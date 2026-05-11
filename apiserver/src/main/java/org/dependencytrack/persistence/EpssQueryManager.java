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
package org.dependencytrack.persistence;

import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class EpssQueryManager extends QueryManager implements IQueryManager {

    EpssQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    public @Nullable Epss getEffectiveEpssForVuln(String source, String vulnId) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT "CVE"
                     , "SCORE"
                     , "PERCENTILE"
                  FROM (
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "EPSS" AS ee
                     WHERE ? = 'NVD'
                       AND ee."CVE" = ?
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
                     WHERE ? != 'NVD'
                       AND va."SOURCE" = ?
                       AND va."VULN_ID" = ?
                  ) candidates
                 ORDER BY "SCORE" DESC NULLS LAST
                        , "PERCENTILE" DESC NULLS LAST
                        , "CVE"
                 LIMIT 1
                """);
        query.setParameters(source, vulnId, source, source, vulnId);
        return executeAndCloseResultUnique(query, Epss.class);
    }

    public record EffectiveEpssRow(
            String vulnSource,
            String vulnId,
            String cve,
            BigDecimal score,
            BigDecimal percentile) {
    }

    public Map<VulnerabilityKey, Epss> getEffectiveEpssForVulns(Collection<VulnerabilityKey> keys) {
        if (keys.isEmpty()) {
            return Map.of();
        }

        final var sources = new String[keys.size()];
        final var vulnIds = new String[keys.size()];

        int i = 0;
        for (final VulnerabilityKey key : keys) {
            sources[i] = key.source().name();
            vulnIds[i] = key.vulnId();
            i++;
        }

        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT t."VULN_SOURCE" AS "vulnSource"
                     , t."VULN_ID" AS "vulnId"
                     , best."CVE" AS "cve"
                     , best."SCORE" AS "score"
                     , best."PERCENTILE" AS "percentile"
                  FROM UNNEST(?, ?)
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
                """);
        query.setParameters(sources, vulnIds);
        final List<EffectiveEpssRow> rows = executeAndCloseResultList(query, EffectiveEpssRow.class);

        final var result = new HashMap<VulnerabilityKey, Epss>(rows.size());
        for (final EffectiveEpssRow row : rows) {
            final var key = new VulnerabilityKey(
                    row.vulnId(),
                    Vulnerability.Source.valueOf(row.vulnSource()));
            result.put(key, new Epss(row.cve(), row.score(), row.percentile()));
        }

        return result;
    }

}
