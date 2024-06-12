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
package org.dependencytrack.notification.vo;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityDetails;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityOverview;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilitySummary;
import org.dependencytrack.persistence.QueryManager;

public class ScheduledNewVulnerabilitiesIdentified {
    private final VulnerabilityOverview overview;
    private final VulnerabilitySummary summary;
    private final VulnerabilityDetails details;

    public ScheduledNewVulnerabilitiesIdentified(final List<Project> affectedProjects, ZonedDateTime lastExecution) {
        try (var qm = new QueryManager()) {
            Map<Project, List<Finding>> affectedProjectFindings = new LinkedHashMap<>();
            for (Project project : affectedProjects) {
                var findings = qm.getFindingsSince(project, true, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
                affectedProjectFindings.put(project, findings);
            }
            this.overview = new VulnerabilityOverview(affectedProjectFindings);
            this.summary = new VulnerabilitySummary(affectedProjectFindings);
            this.details = new VulnerabilityDetails(affectedProjectFindings);
        }

    }

    public VulnerabilityOverview getOverview() {
        return overview;
    }

    public VulnerabilitySummary getSummary() {
        return summary;
    }

    public VulnerabilityDetails getDetails() {
        return details;
    }
}
