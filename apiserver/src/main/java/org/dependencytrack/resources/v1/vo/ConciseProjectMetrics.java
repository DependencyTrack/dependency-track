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
package org.dependencytrack.resources.v1.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.persistence.jdbi.ProjectDao.ConciseProjectMetricsRow;

/**
 * @since 5.0.0
 */
@Schema(description = "A concise representation of a project's metrics")
public record ConciseProjectMetrics(
        @Schema(description = "Total number of components", requiredMode = Schema.RequiredMode.REQUIRED) int components,
        @Schema(description = "Number of vulnerabilities with critical severity", requiredMode = Schema.RequiredMode.REQUIRED) int critical,
        @Schema(description = "Number of vulnerabilities with high severity", requiredMode = Schema.RequiredMode.REQUIRED) int high,
        @Schema(description = "Number of vulnerabilities with low severity", requiredMode = Schema.RequiredMode.REQUIRED) int low,
        @Schema(description = "Number of vulnerabilities with medium severity", requiredMode = Schema.RequiredMode.REQUIRED) int medium,
        @Schema(description = "Number of policy violations with status FAIL", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsFail,
        @Schema(description = "Number of policy violations with status WARN", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsInfo,
        @Schema(description = "Number of license policy violations", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsLicenseTotal,
        @Schema(description = "Number of operational policy violations", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsOperationalTotal,
        @Schema(description = "Number of security policy violations", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsSecurityTotal,
        @Schema(description = "Total number of policy violations", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsTotal,
        @Schema(description = "Number of policy violations with status WARN", requiredMode = Schema.RequiredMode.REQUIRED) int policyViolationsWarn,
        @Schema(description = "The inherited risk score", requiredMode = Schema.RequiredMode.REQUIRED) double inheritedRiskScore,
        @Schema(description = "Number of vulnerabilities with unassigned severity", requiredMode = Schema.RequiredMode.REQUIRED) int unassigned,
        @Schema(description = "Total number of vulnerabilities", requiredMode = Schema.RequiredMode.REQUIRED) int vulnerabilities
) {

    public ConciseProjectMetrics(final ConciseProjectMetricsRow row) {
        this(row.components(), row.critical(), row.high(), row.low(), row.medium(),
                row.policyViolationsFail(), row.policyViolationsInfo(), row.policyViolationsLicenseTotal(),
                row.policyViolationsOperationalTotal(), row.policyViolationsSecurityTotal(), row.policyViolationsTotal(),
                row.policyViolationsWarn(), row.riskScore(), row.unassigned(), row.vulnerabilities());
    }

}
