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

import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public interface MetricsTestDao extends SqlObject {

    @SqlQuery("""
            INSERT INTO "PROJECTMETRICS"(
              "COMPONENTS"
            , "CRITICAL"
            , "FINDINGS_AUDITED"
            , "FINDINGS_TOTAL"
            , "FINDINGS_UNAUDITED"
            , "FIRST_OCCURRENCE"
            , "HIGH"
            , "LAST_OCCURRENCE"
            , "LOW"
            , "MEDIUM"
            , "POLICYVIOLATIONS_AUDITED"
            , "POLICYVIOLATIONS_FAIL"
            , "POLICYVIOLATIONS_INFO"
            , "POLICYVIOLATIONS_LICENSE_AUDITED"
            , "POLICYVIOLATIONS_LICENSE_TOTAL"
            , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
            , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
            , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
            , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
            , "POLICYVIOLATIONS_SECURITY_AUDITED"
            , "POLICYVIOLATIONS_SECURITY_TOTAL"
            , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
            , "POLICYVIOLATIONS_TOTAL"
            , "POLICYVIOLATIONS_UNAUDITED"
            , "POLICYVIOLATIONS_WARN"
            , "PROJECT_ID"
            , "RISKSCORE"
            , "SUPPRESSED"
            , "UNASSIGNED_SEVERITY"
            , "VULNERABILITIES"
            , "VULNERABLECOMPONENTS"
            ) VALUES (
              :components
            , :critical
            , :findingsAudited
            , :findingsTotal
            , :findingsUnaudited
            , :firstOccurrence
            , :high
            , :lastOccurrence
            , :low
            , :medium
            , :policyViolationsAudited
            , :policyViolationsFail
            , :policyViolationsInfo
            , :policyViolationsLicenseAudited
            , :policyViolationsLicenseTotal
            , :policyViolationsLicenseUnaudited
            , :policyViolationsOperationalAudited
            , :policyViolationsOperationalTotal
            , :policyViolationsOperationalUnaudited
            , :policyViolationsSecurityAudited
            , :policyViolationsSecurityTotal
            , :policyViolationsSecurityUnaudited
            , :policyViolationsTotal
            , :policyViolationsUnaudited
            , :policyViolationsWarn
            , :projectId
            , :inheritedRiskScore
            , :suppressed
            , :unassigned
            , :vulnerabilities
            , :vulnerableComponents
            )
            RETURNING *
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics createProjectMetrics(@BindBean ProjectMetrics projectMetrics);

    @SqlQuery("""
            INSERT INTO "DEPENDENCYMETRICS"(
              "COMPONENT_ID"
            , "PROJECT_ID"
            , "FIRST_OCCURRENCE"
            , "LAST_OCCURRENCE"
            , "CRITICAL"
            , "FINDINGS_AUDITED"
            , "FINDINGS_TOTAL"
            , "FINDINGS_UNAUDITED"
            , "HIGH"
            , "LOW"
            , "MEDIUM"
            , "POLICYVIOLATIONS_AUDITED"
            , "POLICYVIOLATIONS_FAIL"
            , "POLICYVIOLATIONS_INFO"
            , "POLICYVIOLATIONS_LICENSE_AUDITED"
            , "POLICYVIOLATIONS_LICENSE_TOTAL"
            , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
            , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
            , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
            , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
            , "POLICYVIOLATIONS_SECURITY_AUDITED"
            , "POLICYVIOLATIONS_SECURITY_TOTAL"
            , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
            , "POLICYVIOLATIONS_TOTAL"
            , "POLICYVIOLATIONS_UNAUDITED"
            , "POLICYVIOLATIONS_WARN"
            , "RISKSCORE"
            , "SUPPRESSED"
            , "UNASSIGNED_SEVERITY"
            , "VULNERABILITIES"
            ) VALUES (
              :componentId
            , :projectId
            , :firstOccurrence
            , :lastOccurrence
            , :critical
            , :findingsAudited
            , :findingsTotal
            , :findingsUnaudited
            , :high
            , :low
            , :medium
            , :policyViolationsAudited
            , :policyViolationsFail
            , :policyViolationsInfo
            , :policyViolationsLicenseAudited
            , :policyViolationsLicenseTotal
            , :policyViolationsLicenseUnaudited
            , :policyViolationsOperationalAudited
            , :policyViolationsOperationalTotal
            , :policyViolationsOperationalUnaudited
            , :policyViolationsSecurityAudited
            , :policyViolationsSecurityTotal
            , :policyViolationsSecurityUnaudited
            , :policyViolationsTotal
            , :policyViolationsUnaudited
            , :policyViolationsWarn
            , :inheritedRiskScore
            , :suppressed
            , :unassigned
            , :vulnerabilities
            )
            RETURNING *
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics createDependencyMetrics(@BindBean DependencyMetrics dependencyMetrics);

    default void createMetricsPartitionsForDate(String tableName, LocalDate targetDate) {
        LocalDate nextDay = targetDate.plusDays(1);
        String partitionSuffix = targetDate.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String partitionName = tableName + "_" + partitionSuffix;
        String sql = String.format("""
            CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
            FOR VALUES FROM (CAST('%s' AS timestamp) AT TIME ZONE 'UTC') TO (CAST('%s' AS timestamp) AT TIME ZONE 'UTC');
        """,
                "\"" + partitionName + "\"",
                "\"" + tableName + "\"",
                targetDate,
                nextDay
        );
        getHandle().execute(sql);
    }

    default void createPartitionForDaysAgo(String tableName, int daysAgo) {
        LocalDate targetDate = LocalDate.now(ZoneOffset.UTC).minusDays(daysAgo);
        createMetricsPartitionsForDate(tableName, targetDate);
    }
}
