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
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * Main part of the ScheduledPolicyViolationsIdentified Template Models.
 * Contains the separate parts used in the template to display the new policy
 * violations identified since the last notification.
 *
 * @since 4.13.0
 */
public record ScheduledPolicyViolationsIdentified(
        Overview overview,
        Summary summary,
        Details details,
        long ruleId) implements ScheduledNotificationSubject {

    public record Overview(
            int affectedProjectsCount,
            int affectedComponentsCount,
            int newViolationsCount,
            Map<PolicyViolation.Type, Integer> newViolationsCountByType,
            int suppressedNewViolationsCount) {

        public static Overview of(final Map<Project, List<ProjectPolicyViolation>> violationsByProject) {
            final int affectedProjectsCount = violationsByProject.size();
            int affectedComponentsCount = 0;
            int newViolationsCount = 0;
            int suppressedNewViolationsCount = 0;

            final var newViolationsByType = new EnumMap<PolicyViolation.Type, Integer>(PolicyViolation.Type.class);
            for (final PolicyViolation.Type violationType : PolicyViolation.Type.values()) {
                newViolationsByType.put(violationType, 0);
            }

            final var componentIdsSeen = new HashSet<Long>();

            for (final List<ProjectPolicyViolation> violations : violationsByProject.values()) {
                for (final ProjectPolicyViolation violation : violations) {
                    if (componentIdsSeen.add(violation.component().getId())) {
                        affectedComponentsCount++;
                    }

                    if (violation.isSuppressed()) {
                        suppressedNewViolationsCount++;
                    } else {
                        newViolationsByType.merge(violation.violationType(), 1, Integer::sum);
                        newViolationsCount++;
                    }
                }
            }

            return new Overview(
                    affectedProjectsCount,
                    affectedComponentsCount,
                    newViolationsCount,
                    newViolationsByType,
                    suppressedNewViolationsCount);
        }

    }

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

    public record ProjectSummary(
            Map<PolicyViolation.Type, Integer> newViolationsCountByType,
            Map<PolicyViolation.Type, Integer> suppressedNewViolationsCountByType,
            Map<PolicyViolation.Type, Integer> totalNewViolationsCountByType) {

        private static ProjectSummary of(final Collection<ProjectPolicyViolation> violations) {
            final Map<PolicyViolation.Type, Integer> newViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);
            final Map<PolicyViolation.Type, Integer> suppressedNewViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);
            final Map<PolicyViolation.Type, Integer> totalNewViolationsCountByType = new EnumMap<>(PolicyViolation.Type.class);

            for (final PolicyViolation.Type violationType : PolicyViolation.Type.values()) {
                newViolationsCountByType.put(violationType, 0);
                suppressedNewViolationsCountByType.put(violationType, 0);
                totalNewViolationsCountByType.put(violationType, 0);
            }

            for (final ProjectPolicyViolation violation : violations) {
                totalNewViolationsCountByType.merge(violation.violationType(), 1, Integer::sum);

                if (violation.isSuppressed()) {
                    suppressedNewViolationsCountByType.merge(violation.violationType(), 1, Integer::sum);
                } else {
                    newViolationsCountByType.merge(violation.violationType(), 1, Integer::sum);
                }
            }

            return new ProjectSummary(
                    newViolationsCountByType,
                    suppressedNewViolationsCountByType,
                    totalNewViolationsCountByType);
        }

    }

    public record Details(Map<Project, List<ProjectPolicyViolation>> violationsByProject) {
    }

    public static ScheduledPolicyViolationsIdentified of(
            final Map<Project, List<ProjectPolicyViolation>> violationsByProject,
            final long ruleId) {
        return new ScheduledPolicyViolationsIdentified(
                Overview.of(violationsByProject),
                Summary.of(violationsByProject),
                new Details(violationsByProject),
                ruleId);
    }

    @Override
    public long getRuleId() {
        return ruleId;
    }

}