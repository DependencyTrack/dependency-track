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

import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * Main part of the ScheduledNewVulnerabilitiesIdentified Template Models.
 * Contains the separate parts used in the template to display the new
 * vulnerabilities identified since the last notification.
 *
 * @since 4.13.0
 */
public record ScheduledNewVulnerabilitiesIdentified(
        Overview overview,
        Summary summary,
        Details details,
        long ruleId) implements ScheduledNotificationSubject {

    public record Overview(
            int affectedProjectsCount,
            int affectedComponentsCount,
            int newVulnerabilitiesCount,
            Map<Severity, Integer> newVulnerabilitiesCountBySeverity,
            int suppressedNewVulnerabilitiesCount) {

        private static Overview of(final Map<Project, List<ProjectFinding>> findingsByProject) {
            int affectedProjectsCount = findingsByProject.size();
            int affectedComponentsCount = 0;
            int newVulnerabilitiesCount = 0;
            int suppressedNewVulnerabilitiesCount = 0;

            final var newVulnerabilitiesCountBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            for (final Severity severity : Severity.values()) {
                newVulnerabilitiesCountBySeverity.put(severity, 0);
            }

            final var componentIdsSeen = new HashSet<Long>();

            for (final List<ProjectFinding> findings : findingsByProject.values()) {
                for (final ProjectFinding finding : findings) {
                    if (componentIdsSeen.add(finding.component().getId())) {
                        affectedComponentsCount++;
                    }

                    if (finding.isSuppressed()) {
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
                    suppressedNewVulnerabilitiesCount);
        }

    }

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

    public record ProjectSummary(
            Map<Severity, Integer> newVulnerabilitiesCountBySeverity,
            Map<Severity, Integer> suppressedNewVulnerabilitiesCountBySeverity,
            Map<Severity, Integer> totalNewVulnerabilitiesCountBySeverity) {

        private static ProjectSummary of(final List<ProjectFinding> findings) {
            final var newVulnerabilitiesBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            final var suppressedNewVulnerabilitiesBySeverity = new EnumMap<Severity, Integer>(Severity.class);
            final var totalNewVulnerabilitiesCountBySeverity = new EnumMap<Severity, Integer>(Severity.class);

            for (final Severity severity : Severity.values()) {
                newVulnerabilitiesBySeverity.put(severity, 0);
                suppressedNewVulnerabilitiesBySeverity.put(severity, 0);
                totalNewVulnerabilitiesCountBySeverity.put(severity, 0);
            }

            for (final ProjectFinding finding : findings) {
                final Severity severity = finding.vulnerability().getSeverity();
                totalNewVulnerabilitiesCountBySeverity.merge(severity, 1, Integer::sum);

                if (finding.isSuppressed()) {
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

    public record Details(Map<Project, List<ProjectFinding>> findingsByProject) {
    }

    public static ScheduledNewVulnerabilitiesIdentified of(
            final Map<Project, List<ProjectFinding>> findingsByProject,
            final long ruleId) {
        return new ScheduledNewVulnerabilitiesIdentified(
                Overview.of(findingsByProject),
                Summary.of(findingsByProject),
                new Details(findingsByProject),
                ruleId);
    }

    @Override
    public long getRuleId() {
        return ruleId;
    }

}
