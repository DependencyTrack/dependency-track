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

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;

import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * @since 4.13.0
 */
public record NewVulnerabilitiesSummary(
        Overview overview,
        Summary summary,
        Details details,
        Date since,
        long ruleId) implements ScheduledNotificationSubject {

    /**
     * High-level overview of the contents of this summary.
     *
     * @param affectedProjectsCount             Number of projects affected by at least one vulnerability.
     * @param affectedComponentsCount           Number of components affected by at least one vulnerability.
     * @param newVulnerabilitiesCount           Number of new, non-suppressed vulnerabilities.
     * @param newVulnerabilitiesCountBySeverity Number of new, non-suppressed vulnerabilities by their {@link Severity}.
     * @param suppressedNewVulnerabilitiesCount Number of new, suppressed vulnerabilities.
     * @param totalNewVulnerabilitiesCount      Total number of new vulnerabilities (suppressed and unsuppressed).
     */
    public record Overview(
            int affectedProjectsCount,
            int affectedComponentsCount,
            int newVulnerabilitiesCount,
            Map<Severity, Integer> newVulnerabilitiesCountBySeverity,
            int suppressedNewVulnerabilitiesCount,
            int totalNewVulnerabilitiesCount) {

        private static Overview of(final Map<Project, List<ProjectFinding>> findingsByProject) {
            int affectedProjectsCount = findingsByProject.size();
            int affectedComponentsCount = 0;
            int newVulnerabilitiesCount = 0;
            int suppressedNewVulnerabilitiesCount = 0;
            int totalNewVulnerabilitiesCount = 0;

            final var newVulnerabilitiesCountBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            final var componentIdsSeen = new HashSet<Long>();

            for (final List<ProjectFinding> findings : findingsByProject.values()) {
                for (final ProjectFinding finding : findings) {
                    if (componentIdsSeen.add(finding.component().getId())) {
                        affectedComponentsCount++;
                    }

                    totalNewVulnerabilitiesCount++;
                    if (finding.suppressed()) {
                        suppressedNewVulnerabilitiesCount++;
                    } else {
                        newVulnerabilitiesCountBySeverity.merge(finding.vulnerability().getSeverity(), 1, Integer::sum);
                        newVulnerabilitiesCount++;
                    }
                }
            }

            return new Overview(
                    affectedProjectsCount,
                    affectedComponentsCount,
                    newVulnerabilitiesCount,
                    newVulnerabilitiesCountBySeverity,
                    suppressedNewVulnerabilitiesCount,
                    totalNewVulnerabilitiesCount);
        }

    }

    /**
     * @param projectSummaries High-level summaries of all affected {@link Project}s.
     */
    public record Summary(Map<Project, ProjectSummary> projectSummaries) {

        private static Summary of(final Map<Project, List<ProjectFinding>> findingsByProject) {
            final var projectSummaries = new HashMap<Project, ProjectSummary>(findingsByProject.size());

            for (final Map.Entry<Project, List<ProjectFinding>> entry : findingsByProject.entrySet()) {
                final Project project = entry.getKey();
                final List<ProjectFinding> findings = entry.getValue();

                final ProjectSummary projectSummary = ProjectSummary.of(findings);
                projectSummaries.put(project, projectSummary);
            }

            return new Summary(projectSummaries);
        }

    }

    /**
     * High-level summary for a {@link Project}.
     *
     * @param newVulnerabilitiesCountBySeverity           Number of new, non-suppressed vulnerabilities by their {@link Severity}.
     * @param suppressedNewVulnerabilitiesCountBySeverity Number of new, suppressed vulnerabilities by their {@link Severity}.
     * @param totalNewVulnerabilitiesCountBySeverity      Total number of new vulnerabilities by their {@link Severity}.
     */
    public record ProjectSummary(
            Map<Severity, Integer> newVulnerabilitiesCountBySeverity,
            Map<Severity, Integer> suppressedNewVulnerabilitiesCountBySeverity,
            Map<Severity, Integer> totalNewVulnerabilitiesCountBySeverity) {

        private static ProjectSummary of(final List<ProjectFinding> findings) {
            final var newVulnerabilitiesBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            final var suppressedNewVulnerabilitiesBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            final var totalNewVulnerabilitiesCountBySeverity = new EnumMap<Severity, Integer>(Severity.class);

            for (final ProjectFinding finding : findings) {
                final Severity severity = finding.vulnerability().getSeverity();
                totalNewVulnerabilitiesCountBySeverity.merge(severity, 1, Integer::sum);

                if (finding.suppressed()) {
                    suppressedNewVulnerabilitiesBySeverity.merge(severity, 1, Integer::sum);
                } else {
                    newVulnerabilitiesBySeverity.merge(severity, 1, Integer::sum);
                }
            }

            return new ProjectSummary(
                    newVulnerabilitiesBySeverity,
                    suppressedNewVulnerabilitiesBySeverity,
                    totalNewVulnerabilitiesCountBySeverity);
        }

    }

    /**
     * @param findingsByProject All new findings grouped by the {@link Project} they're affecting.
     */
    public record Details(Map<Project, List<ProjectFinding>> findingsByProject) {
    }

    public static NewVulnerabilitiesSummary of(
            final Map<Project, List<ProjectFinding>> findingsByProject,
            final Date since,
            final long ruleId) {
        return new NewVulnerabilitiesSummary(
                Overview.of(findingsByProject),
                Summary.of(findingsByProject),
                new Details(findingsByProject),
                since,
                ruleId);
    }

    @Override
    public long getRuleId() {
        return ruleId;
    }

}
