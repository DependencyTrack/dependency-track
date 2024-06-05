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

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;

public final class Overview {
    private final Integer affectedProjectsCount;
    private final Integer newVulnerabilitiesCount;
    private final Map<Severity, Integer> newVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
    private final Integer affectedComponentsCount;
    private final Integer suppressedNewVulnerabilitiesCount;

    public Overview(final List<Project> affectedProjects, ZonedDateTime lastExecution) {
        var componentCache = new HashSet<Component>();
        var vulnerabilityCache = new HashSet<Vulnerability>();
        var suppressedVulnerabilityCache = new HashSet<Vulnerability>();

        try (var qm = new QueryManager()) {
            for (Project project : affectedProjects) {
                var findings = qm.getFindingsSince(project, false, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
                for (Finding finding : findings) {
                    Component component = qm.getObjectByUuid(Component.class, (String) finding.getComponent().get("uuid"));
                    componentCache.add(component);

                    Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String) finding.getVulnerability().get("uuid"));
                    if (finding.getAnalysis().get("isSuppressed") instanceof Boolean suppressed) {
                        if (suppressed) {
                            suppressedVulnerabilityCache.add(vulnerability);
                        } else {
                            vulnerabilityCache.add(vulnerability);
                            newVulnerabilitiesBySeverity.merge(vulnerability.getSeverity(), 1, Integer::sum);
                        }
                    }
                }
            }
        }

        affectedProjectsCount = affectedProjects.size();
        newVulnerabilitiesCount = vulnerabilityCache.size();
        affectedComponentsCount = componentCache.size();
        suppressedNewVulnerabilitiesCount = suppressedVulnerabilityCache.size();
    }

    public Integer getAffectedProjectsCount() {
        return affectedProjectsCount;
    }

    public Integer getNewVulnerabilitiesCount() {
        return newVulnerabilitiesCount;
    }

    public Map<Severity, Integer> getNewVulnerabilitiesBySeverity() {
        return newVulnerabilitiesBySeverity;
    }

    public Integer getAffectedComponentsCount() {
        return affectedComponentsCount;
    }

    public Integer getSuppressedNewVulnerabilitiesCount() {
        return suppressedNewVulnerabilitiesCount;
    }
}
