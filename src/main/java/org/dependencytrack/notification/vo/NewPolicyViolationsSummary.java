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

import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;

import java.util.Collection;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * @since 4.13.0
 */
public record NewPolicyViolationsSummary(
        Overview overview,
        Summary summary,
        Details details,
        Date since,
        long ruleId) implements ScheduledNotificationSubject {

    /**
     * High-level overview of the contents of this summary.
     *
     * @param affectedProjectsCount        Number of projects affected by at least one violation.
     * @param affectedComponentsCount      Number of components affected by at least one violation.
     * @param newViolationsCount           Number of new, non-suppressed violations.
     * @param newViolationsCountByType     Number of new, non-suppressed violations by their {@link PolicyViolation.Type}.
     * @param suppressedNewViolationsCount Number of new, suppressed violations.
     * @param totalNewViolationsCount      Total number of new violations (suppressed and unsuppressed).
     */
    public record Overview(
            int affectedProjectsCount,
            int affectedComponentsCount,
            int newViolationsCount,
            Map<PolicyViolation.Type, Integer> newViolationsCountByType,
            int suppressedNewViolationsCount,
            int totalNewViolationsCount) {

        public static Overview of(final Map<Project, List<ProjectPolicyViolation>> violationsByProject) {
            final int affectedProjectsCount = violationsByProject.size();
            int affectedComponentsCount = 0;
            int newViolationsCount = 0;
            int suppressedNewViolationsCount = 0;
            int totalNewViolationsCount = 0;

            final var newViolationsByType = new EnumMap<PolicyViolation.Type, Integer>(PolicyViolation.Type.class);
            final var componentIdsSeen = new HashSet<Long>();

            for (final List<ProjectPolicyViolation> violations : violationsByProject.values()) {
                for (final ProjectPolicyViolation violation : violations) {
                    if (componentIdsSeen.add(violation.component().getId())) {
                        affectedComponentsCount++;
                    }

                    totalNewViolationsCount++;
                    if (violation.suppressed()) {
                        suppressedNewViolationsCount++;
                    } else {
                        newViolationsByType.merge(violation.type(), 1, Integer::sum);
                        newViolationsCount++;
                    }
                }
            }

            return new Overview(
                    affectedProjectsCount,
                    affectedComponentsCount,
                    newViolationsCount,
                    newViolationsByType,
                    suppressedNewViolationsCount,
                    totalNewViolationsCount);
        }

    }

    /**
     * @param projectSummaries High-level summaries of all affected projects.
     */
    public record Summary(Map<Project, ProjectSummary> projectSummaries) {

        private static Summary of(final Map<Project, List<ProjectPolicyViolation>> violationsByProject) {
            final var projectSummaries = new HashMap<Project, ProjectSummary>(violationsByProject.size());

            for (final var entry : violationsByProject.entrySet()) {
                final Project project = entry.getKey();
                final List<ProjectPolicyViolation> violations = entry.getValue();

                final var projectSummary = ProjectSummary.of(violations);
                projectSummaries.put(project, projectSummary);
            }

            return new Summary(projectSummaries);
        }

    }

    /**
     * High-level summary for a {@link Project}.
     *
     * @param newViolationsCountByType           Number of new, non-suppressed violations by their {@link PolicyViolation.Type}.
     * @param suppressedNewViolationsCountByType Number of new, suppressed violations by their {@link PolicyViolation.Type}.
     * @param totalNewViolationsCountByType      Total number of new violations (suppressed and unsuppressed).
     */
    public record ProjectSummary(
            Map<PolicyViolation.Type, Integer> newViolationsCountByType,
            Map<PolicyViolation.Type, Integer> suppressedNewViolationsCountByType,
            Map<PolicyViolation.Type, Integer> totalNewViolationsCountByType) {

        private static ProjectSummary of(final Collection<ProjectPolicyViolation> violations) {
            final Map<PolicyViolation.Type, Integer> newViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);
            final Map<PolicyViolation.Type, Integer> suppressedNewViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);
            final Map<PolicyViolation.Type, Integer> totalNewViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);

            for (final ProjectPolicyViolation violation : violations) {
                totalNewViolationsCountByType.merge(violation.type(), 1, Integer::sum);

                if (violation.suppressed()) {
                    suppressedNewViolationsCountByType.merge(violation.type(), 1, Integer::sum);
                } else {
                    newViolationsCountByType.merge(violation.type(), 1, Integer::sum);
                }
            }

            return new ProjectSummary(
                    newViolationsCountByType,
                    suppressedNewViolationsCountByType,
                    totalNewViolationsCountByType);
        }

    }

    /**
     * @param violationsByProject All new violations grouped by the {@link Project} they're affecting.
     */
    public record Details(Map<Project, List<ProjectPolicyViolation>> violationsByProject) {
    }

    public static NewPolicyViolationsSummary of(
            final Map<Project, List<ProjectPolicyViolation>> violationsByProject,
            final Date since,
            final long ruleId) {
        return new NewPolicyViolationsSummary(
                Overview.of(violationsByProject),
                Summary.of(violationsByProject),
                new Details(violationsByProject),
                since,
                ruleId);
    }

    @Override
    public long getRuleId() {
        return ruleId;
    }

}