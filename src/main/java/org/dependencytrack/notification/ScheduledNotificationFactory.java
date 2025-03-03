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
package org.dependencytrack.notification;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationDetails;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationOverview;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationSummary;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationSummaryInfo;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityDetails;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityDetailsInfo;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityOverview;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilitySummary;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilitySummaryInfo;
import org.dependencytrack.notification.vo.ScheduledNewVulnerabilitiesIdentified;
import org.dependencytrack.notification.vo.ScheduledPolicyViolationsIdentified;
import org.dependencytrack.persistence.QueryManager;

public class ScheduledNotificationFactory {
    public static ScheduledNewVulnerabilitiesIdentified CreateScheduledVulnerabilitySubject(ScheduledNotificationRule rule, ZonedDateTime lastExecution) {
        Map<Project, List<Finding>> affectedProjectFindings = new LinkedHashMap<>();

        try (var qm = new QueryManager()) {
            var findings = qm.getAllFindingsSince(true, lastExecution.withZoneSameInstant(ZoneOffset.UTC));

            for (Finding finding : findings) {
                var findingProject = qm.getProject(finding.getProjectUuid().toString());

                if (!checkIfProjectShallBeProcessed(findingProject, rule))
                    continue;

                var entry = affectedProjectFindings.get(findingProject);
                if (entry == null) {
                    ArrayList<Finding> initial = new ArrayList<Finding>();
                    initial.add(finding);
                    affectedProjectFindings.put(findingProject, initial);
                } else {
                    entry.add(finding);
                }
            }
        }

        var overview = createVulnerabilityOverview(affectedProjectFindings);
        var summary = createVulnerabilitySummary(affectedProjectFindings);
        var details = createVulnerabilityDetails(affectedProjectFindings);

        return new ScheduledNewVulnerabilitiesIdentified(overview, summary, details);
    }

    public static ScheduledPolicyViolationsIdentified CreateScheduledPolicyViolationSubject(ScheduledNotificationRule rule, ZonedDateTime lastExecution) {
        Map<Project, List<PolicyViolation>> affectedProjectViolations = new LinkedHashMap<>();

        try (var qm = new QueryManager()){
            var violations = qm.getAllPolicyViolationsSince(true, lastExecution);
            
            for (PolicyViolation violation : violations) {
                if (!checkIfProjectShallBeProcessed(violation.getProject(), rule))
                    continue;

                var entry = affectedProjectViolations.get(violation.getProject());
                if (entry == null) {
                    ArrayList<PolicyViolation> initial = new ArrayList<PolicyViolation>();
                    initial.add(violation);
                    affectedProjectViolations.put(violation.getProject(), initial);
                } else {
                    entry.add(violation);
                }
            }
        }

        var overview = createPolicyOverview(affectedProjectViolations);
        var summary = createPolicySummary(affectedProjectViolations);
        var details = createPolicyDetails(affectedProjectViolations);
        
        return new ScheduledPolicyViolationsIdentified(overview, summary, details);
    }

    private static boolean checkIfProjectShallBeProcessed(Project project, ScheduledNotificationRule rule) {
        if (rule.getProjects() == null || rule.getProjects().isEmpty()) {
            return true;
        }
        for (final Project ruleProject : rule.getProjects()) {
            var projectIsMatch = project.getUuid().equals(ruleProject.getUuid());
            var considerChildren = Boolean.TRUE.equals(rule.isNotifyChildren()
                    && checkIfChildrenAreAffected(ruleProject, project.getUuid()));
            if (projectIsMatch || considerChildren) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkIfChildrenAreAffected(Project parent, UUID uuid) {
        boolean isChild = false;
        if (parent.getChildren() == null || parent.getChildren().isEmpty()) {
            return false;
        }
        for (Project child : parent.getChildren()) {
            final boolean isChildActive = child.isActive();
            if ((child.getUuid().equals(uuid) && isChildActive) || isChild) {
                return true;
            }
            isChild = checkIfChildrenAreAffected(child, uuid);
        }
        return isChild;
    }

    private static VulnerabilityOverview createVulnerabilityOverview(Map<Project, List<Finding>> affectedProjectFindings) {
        Integer affectedProjectsCount;
        Integer newVulnerabilitiesCount = 0;
        Map<Severity, Integer> newVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
        Integer affectedComponentsCount = 0;
        Integer suppressedNewVulnerabilitiesCount = 0;

        for (Severity severity : Severity.values()) {
            newVulnerabilitiesBySeverity.put(severity, 0);
        }

        try (var qm = new QueryManager()) {
            for (var findings : affectedProjectFindings.values()) {
                for (Finding finding : findings) {
                    if(finding.getComponent() != null)
                        affectedComponentsCount++;

                    if (finding.getAnalysis().get("isSuppressed") instanceof Boolean suppressed) {
                        if (suppressed) {
                            suppressedNewVulnerabilitiesCount++;
                        } else {
                            newVulnerabilitiesCount++;
                            newVulnerabilitiesBySeverity.merge(
                                    Enum.valueOf(Severity.class, finding.getVulnerability().get("severity").toString()),
                                    1, Integer::sum);
                        }
                    }
                }
            }
        }

        affectedProjectsCount = affectedProjectFindings.size();

        return new VulnerabilityOverview(affectedProjectsCount, newVulnerabilitiesCount, newVulnerabilitiesBySeverity, affectedComponentsCount, suppressedNewVulnerabilitiesCount);
    }

    private static VulnerabilitySummary createVulnerabilitySummary(Map<Project, List<Finding>> affectedProjectFindings) {
        Map<Project, VulnerabilitySummaryInfo> projectSummaryInfoMap = new LinkedHashMap<>();
        try (var qm = new QueryManager()) {
            for (var entry : affectedProjectFindings.entrySet()) {
                var totalProjectFindings = qm.getFindings(entry.getKey());
                projectSummaryInfoMap.put(entry.getKey(), createVulnerabilitySummaryInfo(entry.getValue(), totalProjectFindings));
                
            }
        }
        return new VulnerabilitySummary(projectSummaryInfoMap);
    }

    private static VulnerabilitySummaryInfo createVulnerabilitySummaryInfo(List<Finding> newFindings, List<Finding> totalProjectFindings){
        Map<Severity, Integer> newVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
        Map<Severity, Integer> totalProjectVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);
        Map<Severity, Integer> suppressedNewVulnerabilitiesBySeverity = new EnumMap<>(Severity.class);

        try (var qm = new QueryManager()) {
            for (Finding finding : newFindings) {
                if (finding.getAnalysis().get("isSuppressed") instanceof Boolean suppressed) {
                    var severity = Enum.valueOf(Severity.class, finding.getVulnerability().get("severity").toString());
                    if (suppressed) {
                        suppressedNewVulnerabilitiesBySeverity.merge(severity, 1, Integer::sum);
                    } else {
                        newVulnerabilitiesBySeverity.merge(severity, 1, Integer::sum);
                    }
                }
            }
            for (Finding finding : totalProjectFindings) {
                var severity = Enum.valueOf(Severity.class, finding.getVulnerability().get("severity").toString());
                totalProjectVulnerabilitiesBySeverity.merge(severity, 1, Integer::sum);
            }
        }
        return new VulnerabilitySummaryInfo(newVulnerabilitiesBySeverity, totalProjectVulnerabilitiesBySeverity, suppressedNewVulnerabilitiesBySeverity);
    }

    private static VulnerabilityDetails createVulnerabilityDetails(Map<Project, List<Finding>> affectedProjectFindings) {
        Map<Project, List<VulnerabilityDetailsInfo>> projectDetailsInfoMap = new LinkedHashMap<>();
        for (var entry : affectedProjectFindings.entrySet()) {
            projectDetailsInfoMap.put(entry.getKey(), entry.getValue().stream().map(f -> createVulnerabilityDetailsInfo(f)).toList());
        }
        return new VulnerabilityDetails(projectDetailsInfoMap);
    }

    private static VulnerabilityDetailsInfo createVulnerabilityDetailsInfo(Finding finding) {
        return new VulnerabilityDetailsInfo(finding);
    }

    private static PolicyViolationOverview createPolicyOverview(Map<Project, List<PolicyViolation>> affectedProjectViolations) {
        var affectedComponentsCount = 0;
        var affectedProjectsCount = 0;
        var newViolationsCount = 0;
        var suppressedNewViolationsCount = 0;
        Map<PolicyViolation.Type, Integer> newViolationsByRiskType = new EnumMap<>(PolicyViolation.Type.class);

        for (PolicyViolation.Type riskType : PolicyViolation.Type.values()) {
            newViolationsByRiskType.put(riskType, 0);
        }

        try (var qm = new QueryManager()) {
            for (var violations : affectedProjectViolations.values()) {
                affectedProjectsCount++;
                for (PolicyViolation violation : violations) {
                    if(violation.getComponent() != null)
                        affectedComponentsCount++;

                    var analysis = violation.getAnalysis();
                    if (analysis != null && analysis.isSuppressed()) {
                        suppressedNewViolationsCount++;
                    } else {
                        newViolationsCount++;
                        newViolationsByRiskType.merge(violation.getType(), 1, Integer::sum);
                    }
                }
            }
        }

        return new PolicyViolationOverview(affectedProjectsCount, newViolationsCount, newViolationsByRiskType, affectedComponentsCount, suppressedNewViolationsCount);
    }

    private static PolicyViolationSummary createPolicySummary(Map<Project, List<PolicyViolation>> affectedProjectViolations) {
        Map<Project, PolicyViolationSummaryInfo> affectedProjectSummaries = new LinkedHashMap<>();
        for (var entry : affectedProjectViolations.entrySet()) {
            affectedProjectSummaries.put(entry.getKey(), createPolicySummaryInfo(entry.getValue()));
        }
        return new PolicyViolationSummary(affectedProjectSummaries);
    }
    
    private static PolicyViolationSummaryInfo createPolicySummaryInfo(List<PolicyViolation> violations) {
        Map<PolicyViolation.Type, Integer> newViolationsByRiskType = new EnumMap<>(PolicyViolation.Type.class);
        Map<PolicyViolation.Type, Integer> totalProjectViolationsByRiskType = new EnumMap<>(PolicyViolation.Type.class);
        Map<PolicyViolation.Type, Integer> suppressedNewViolationsByRiskType = new EnumMap<>(PolicyViolation.Type.class);
        
        for (PolicyViolation violation : violations) {
            var analysis = violation.getAnalysis();
            if (analysis != null && analysis.isSuppressed()) {
                suppressedNewViolationsByRiskType.merge(violation.getType(), 1, Integer::sum);
            } else {
                newViolationsByRiskType.merge(violation.getType(), 1, Integer::sum);
            }
            totalProjectViolationsByRiskType.merge(violation.getType(), 1, Integer::sum);
        }

        return new PolicyViolationSummaryInfo(newViolationsByRiskType, totalProjectViolationsByRiskType, suppressedNewViolationsByRiskType);
    }

    private static PolicyViolationDetails createPolicyDetails(Map<Project, List<PolicyViolation>> affectedProjectViolations) {
        return new PolicyViolationDetails(affectedProjectViolations);
    }
}
