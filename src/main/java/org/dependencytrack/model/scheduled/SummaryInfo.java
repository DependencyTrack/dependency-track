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
package org.dependencytrack.model.scheduled;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;

public final class SummaryInfo {
    private final Map<Severity, Integer> newVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
    private final Map<Severity, Integer> totalProjectVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
    private final Map<Severity, Integer> suppressedNewVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);

    public SummaryInfo(final List<Finding> findings) {
        try (var qm = new QueryManager()) {
            for (Finding finding : findings) {
                Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String) finding.getVulnerability().get("uuid"));
                if (finding.getAnalysis().get("isSuppressed") instanceof Boolean suppressed) {
                    if (suppressed) {
                        suppressedNewVulnerabilitiesBySeverity.merge(vulnerability.getSeverity(), 1, Integer::sum);
                    } else {
                        newVulnerabilitiesBySeverity.merge(vulnerability.getSeverity(), 1, Integer::sum);
                    }
                    totalProjectVulnerabilitiesBySeverity.merge(vulnerability.getSeverity(), 1, Integer::sum);
                }
            }
        }
    }

    public Map<Severity, Integer> getNewVulnerabilitiesBySeverity() {
        return newVulnerabilitiesBySeverity;
    }

    public Map<Severity, Integer> getTotalProjectVulnerabilitiesBySeverity() {
        return totalProjectVulnerabilitiesBySeverity;
    }

    public Map<Severity, Integer> getSuppressedNewVulnerabilitiesBySeverity() {
        return suppressedNewVulnerabilitiesBySeverity;
    }
}
