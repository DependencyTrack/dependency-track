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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.event.ScheduledNotificationDispatchEvent;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.vo.ProjectFinding;
import org.dependencytrack.notification.vo.ProjectPolicyViolation;
import org.dependencytrack.notification.vo.ScheduledNewVulnerabilitiesIdentified;
import org.dependencytrack.notification.vo.ScheduledPolicyViolationsIdentified;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.dependencytrack.util.DateUtil;
import org.slf4j.MDC;

import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_RULE_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_RULE_UUID;

/**
 * @since 4.13.0
 */
public class ScheduledNotificationDispatchTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ScheduledNotificationDispatchTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof ScheduledNotificationDispatchEvent)) {
            return;
        }

        try (final var qm = new QueryManager()) {
            final List<NotificationRule> rules = qm.getDueScheduledNotificationRules();
            if (rules.isEmpty()) {
                // TODO: Switch to debug
                LOGGER.info("No scheduled notifications due for dispatch at this time");
                return;
            }

            for (final NotificationRule rule : rules) {
                try (var ignoredMdcRuleUuid = MDC.putCloseable(MDC_NOTIFICATION_RULE_UUID, rule.getUuid().toString());
                     var ignoredMdcRuleName = MDC.putCloseable(MDC_NOTIFICATION_RULE_NAME, rule.getName())) {
                    if (Thread.currentThread().isInterrupted()) {
                        LOGGER.warn("Interrupted before all rules could be processed");
                        return;
                    }

                    // TODO: Switch to debug
                    LOGGER.info("Processing scheduled notification(s) due since " + rule.getScheduleNextDueAt());

                    processRule(qm, rule);
                } catch (RuntimeException e) {
                    LOGGER.error("Failed to process scheduled notification(s) for rule " + rule.getName(), e);
                }
            }
        }
    }

    private void processRule(final QueryManager qm, final NotificationRule rule) {
        final var processedGroups = new HashSet<NotificationGroup>(rule.getNotifyOn().size());

        for (final NotificationGroup group : rule.getNotifyOn()) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.warn("Interrupted before all groups could be processed");
                break;
            }

            try {
                final Notification notification = switch (group) {
                    case NEW_VULNERABILITY -> createNewVulnerabilityNotification(qm, rule);
                    case POLICY_VIOLATION -> createPolicyViolationNotification(qm, rule);
                    default -> throw new IllegalStateException(
                            "Notification group %s is not supported for scheduled dispatch".formatted(group));
                };

                if (notification != null) {
                    Notification.dispatch(notification);
                }

                processedGroups.add(group);
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to dispatch notification for group " + group, e);
            } finally {
                qm.getPersistenceManager().evictAll(false, Project.class);
                qm.getPersistenceManager().evictAll(false, Component.class);
                qm.getPersistenceManager().evictAll(false, Policy.class);
                qm.getPersistenceManager().evictAll(false, PolicyCondition.class);
                qm.getPersistenceManager().evictAll(false, PolicyViolation.class);
                qm.getPersistenceManager().evictAll(false, Vulnerability.class);
            }
        }

        if (!processedGroups.isEmpty()) {
            // Update last execution time after successful operation (even without dispatch)
            // to avoid duplicate notifications in the next run and signalize user indirectly
            // that operation has ended without failure.

            qm.runInTransaction(() -> {
                rule.setScheduleLastFiredAt(new Date());
                rule.updateScheduleNextDueAt();
            });
        }
    }

    private Notification createNewVulnerabilityNotification(final QueryManager qm, final NotificationRule rule) {
        if (rule.getProjects() == null || rule.getProjects().isEmpty()) {
            throw new IllegalStateException(
                    "Scheduled notifications for group %s must be limited to at least one project".formatted(
                            NotificationGroup.NEW_VULNERABILITY));
        }

        final Set<Long> projectIds = getApplicableProjectIds(qm, rule);
        if (projectIds.isEmpty()) {
            LOGGER.warn(""); // TODO: Could happen if all projects are inactive.
            return null;
        }

        // Fetch findings that were attributed since the last notification.
        final List<NewFinding> newFindings = getNewFindingsSince(qm, projectIds, rule.getScheduleLastFiredAt());
        if (Boolean.TRUE.equals(rule.isScheduleSkipUnchanged())) {
            LOGGER.info("No new findings since rule was last processed at %s".formatted(
                    DateUtil.toISO8601(rule.getScheduleLastFiredAt())));
            return null;
        }

        // Identity unique projects, components, and vulnerabilities across all findings.
        final var findingProjectIds = new HashSet<Long>();
        final var findingComponentIds = new HashSet<Long>();
        final var findingVulnerabilityIds = new HashSet<Long>();
        for (final NewFinding newFinding : newFindings) {
            findingProjectIds.add(newFinding.projectId());
            findingComponentIds.add(newFinding.componentId());
            findingVulnerabilityIds.add(newFinding.vulnerabilityId());
        }

        // Fetch projects, components, and vulnerabilities with fields required for notifications.
        // Group them by their respective IDs for more efficient lookups later.
        // Make them transient to get rid of any further ORM overhead.
        final Map<Long, Project> projectById =
                qm.getProjectsForNotificationById(findingProjectIds).stream()
                        .collect(Collectors.toMap(Project::getId, qm::makeTransient));
        final Map<Long, Component> componentById =
                qm.getComponentsForNotificationById(findingComponentIds).stream()
                        .collect(Collectors.toMap(Component::getId, qm::makeTransient));
        final Map<Long, Vulnerability> vulnerabilityById =
                qm.getVulnerabilitiesForNotificationById(findingVulnerabilityIds).stream()
                        .collect(Collectors.toMap(Vulnerability::getId, qm::makeTransient));

        // Populate vulnerability aliases.
        final Map<VulnIdAndSource, Vulnerability> vulnerabilityByVulnIdAndSource =
                vulnerabilityById.values().stream()
                        .collect(Collectors.toMap(
                                vuln -> new VulnIdAndSource(vuln.getVulnId(), vuln.getSource()),
                                Function.identity()));
        final Map<VulnIdAndSource, List<VulnerabilityAlias>> aliasesByVulnIdAndSource =
                qm.getVulnerabilityAliases(vulnerabilityByVulnIdAndSource.keySet());
        for (final VulnIdAndSource vulnIdAndSource : aliasesByVulnIdAndSource.keySet()) {
            final Vulnerability vulnerability = vulnerabilityByVulnIdAndSource.get(vulnIdAndSource);
            final List<VulnerabilityAlias> aliases = aliasesByVulnIdAndSource.get(vulnIdAndSource);
            vulnerability.setAliases(aliases);
        }

        // Assemble project findings.
        final var findingsByProject = new HashMap<Project, List<ProjectFinding>>();
        for (final NewFinding newFinding : newFindings) {
            final Project project = projectById.get(newFinding.projectId());
            final Component component = componentById.get(newFinding.componentId());
            final Vulnerability vulnerability = vulnerabilityById.get(newFinding.vulnerabilityId());

            final var analyzerIdentity = newFinding.analyzerIdentity() != null
                    ? AnalyzerIdentity.valueOf(newFinding.analyzerIdentity())
                    : null;
            final AnalysisState analysisState = newFinding.analysisState() != null
                    ? AnalysisState.valueOf(newFinding.analysisState())
                    : null;
            final boolean isSuppressed = newFinding.isSuppressed() != null && newFinding.isSuppressed();

            findingsByProject.computeIfAbsent(project, ignored -> new ArrayList<>()).add(new ProjectFinding(
                    component, vulnerability, analyzerIdentity, newFinding.attributedOn(), newFinding.referenceUrl(), analysisState, isSuppressed));
        }

        final var subject = ScheduledNewVulnerabilitiesIdentified.of(findingsByProject, rule.getId());

        return new Notification()
                .scope(rule.getScope())
                .group(NotificationGroup.NEW_VULNERABILITY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(/* TODO */ "")
                .content(/* TODO */ "")
                .subject(subject);
    }

    private Notification createPolicyViolationNotification(final QueryManager qm, final NotificationRule rule) {
        if (rule.getProjects() == null || rule.getProjects().isEmpty()) {
            throw new IllegalStateException(
                    "Scheduled notifications for group %s must be limited to at least one project".formatted(
                            NotificationGroup.POLICY_VIOLATION));
        }

        final Set<Long> projectIds = getApplicableProjectIds(qm, rule);
        if (projectIds.isEmpty()) {
            LOGGER.warn(""); // TODO: Could happen if all projects are inactive.
            return null;
        }

        final List<NewPolicyViolation> newViolations =
                getNewPolicyViolationsSince(qm, projectIds, rule.getScheduleLastFiredAt());
        if (Boolean.TRUE.equals(rule.isScheduleSkipUnchanged())) {
            LOGGER.info("No new policy violations since rule was last processed at %s".formatted(
                    DateUtil.toISO8601(rule.getScheduleLastFiredAt())));
            return null;
        }

        // Identity unique projects, components, and policy conditions across all violations.
        final var violationProjectIds = new HashSet<Long>();
        final var violationComponentIds = new HashSet<Long>();
        final var violationPolicyConditionIds = new HashSet<Long>();
        for (final NewPolicyViolation newPolicyViolation : newViolations) {
            violationProjectIds.add(newPolicyViolation.projectId());
            violationComponentIds.add(newPolicyViolation.componentId());
            violationPolicyConditionIds.add(newPolicyViolation.policyConditionId());
        }

        // Fetch projects, components, policy conditions, and (implicitly) policies with fields required for notifications.
        // Group them by their respective IDs for more efficient lookups later.
        // Make them transient to get rid of any further ORM overhead.
        final Map<Long, Project> projectById =
                qm.getProjectsForNotificationById(violationProjectIds).stream()
                        .collect(Collectors.toMap(Project::getId, qm::makeTransient));
        final Map<Long, Component> componentById =
                qm.getComponentsForNotificationById(violationComponentIds).stream()
                        .collect(Collectors.toMap(Component::getId, qm::makeTransient));
        final Map<Long, PolicyCondition> policyConditionById =
                qm.getPolicyConditionsForNotificationById(violationPolicyConditionIds).stream()
                        .collect(Collectors.toMap(
                                PolicyCondition::getId,
                                condition -> {
                                    qm.makeTransient(condition.getPolicy());
                                    qm.makeTransient(condition);
                                    return condition;
                                }));

        // Assemble project policy violations.
        final var violationsByProject = new HashMap<Project, List<ProjectPolicyViolation>>();
        for (final NewPolicyViolation newViolation : newViolations) {
            final Project project = projectById.get(newViolation.projectId());
            final Component component = componentById.get(newViolation.componentId());
            final PolicyCondition policyCondition = policyConditionById.get(newViolation.policyConditionId());

            final PolicyViolation.Type violationType = newViolation.violationType() != null
                    ? PolicyViolation.Type.valueOf(newViolation.violationType().name())
                    : null;
            final ViolationAnalysisState analysisState = newViolation.analysisState() != null
                    ? ViolationAnalysisState.valueOf(newViolation.analysisState().name())
                    : null;
            final boolean isSuppressed = newViolation.isSuppressed() != null && newViolation.isSuppressed();

            violationsByProject.computeIfAbsent(project, ignored -> new ArrayList<>()).add(new ProjectPolicyViolation(
                    component, policyCondition, violationType, newViolation.timestamp(), analysisState, isSuppressed));
        }

        final var subject = ScheduledPolicyViolationsIdentified.of(violationsByProject, rule.getId());

        return new Notification()
                .scope(rule.getScope())
                .group(NotificationGroup.POLICY_VIOLATION)
                .level(NotificationLevel.INFORMATIONAL)
                .title(/* TODO */ "")
                .content(/* TODO */ "")
                .subject(subject);
    }

    private Set<Long> getApplicableProjectIds(final QueryManager qm, final NotificationRule rule) {
        if (rule.getProjects() == null || rule.getProjects().isEmpty()) {
            return Collections.emptySet();
        }

        // TODO: This should be solved with a recursive CTE,
        //  but it's too much of a hassle getting it to work across
        //  all the RDBMSes we have to support still.

        final var projectIds = new HashSet<Long>();
        for (final Project project : rule.getProjects()) {
            if (!project.isActive()) {
                continue;
            }

            projectIds.add(project.getId());

            if (rule.isNotifyChildren()) {
                projectIds.addAll(getActiveChildProjectIds(qm, project.getId()));
            }
        }

        return projectIds;
    }

    private List<Long> getActiveChildProjectIds(final QueryManager qm, final long parentProjectId) {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("parent.id == :parentId && active");
        query.setParameters(parentProjectId);
        query.setResult("id");

        final List<Long> childProjectIds;
        try {
            childProjectIds = new ArrayList<>(query.executeResultList(Long.class));
        } finally {
            query.closeAll();
        }

        for (final long childProjectId : childProjectIds) {
            childProjectIds.addAll(getActiveChildProjectIds(qm, childProjectId));
        }

        return childProjectIds;
    }

    public record NewFinding(
            long projectId,
            long componentId,
            long vulnerabilityId,
            String analyzerIdentity,
            Date attributedOn,
            String referenceUrl,
            String analysisState,
            Boolean isSuppressed) {
    }

    private List<NewFinding> getNewFindingsSince(
            final QueryManager qm,
            final Collection<Long> projectIds,
            final Date sinceAttributedOn) {
        final var projectIdCondition = new StringJoiner(" OR ", "(", ")");
        final var queryParams = new HashMap<String, Object>(projectIds.size() + 1);
        queryParams.put("sinceAttributedOn", sinceAttributedOn);

        int projectIdIndex = 0;
        for (final Long projectId : projectIds) {
            final int index = projectIdIndex++;
            projectIdCondition.add("\"COMPONENT\".\"PROJECT_ID\" = :projectId" + index);
            queryParams.put("projectId" + index, projectId);
        }

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, /* language=SQL */ """
                SELECT "COMPONENT"."PROJECT_ID" AS "projectId"
                     , "COMPONENT"."ID" AS "componentId"
                     , "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" AS "vulnabilityId"
                     , "FINDINGATTRIBUTION"."ANALYZERIDENTITY" AS "analyzerIdentity"
                     , "FINDINGATTRIBUTION"."ATTRIBUTED_ON" AS "attributedOn"
                     , "FINDINGATTRIBUTION"."REFERENCE_URL" AS "referenceUrl"
                     , "ANALYSIS"."STATE" AS "analysisState"
                     , "ANALYSIS"."SUPPRESSED" AS "isSuppressed"
                  FROM "COMPONENTS_VULNERABILITIES"
                 INNER JOIN "COMPONENT"
                    ON "COMPONENT"."PROJECT_ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
                 INNER JOIN "FINDINGATTRIBUTION"
                    ON "FINDINGATTRIBUTION"."COMPONENT_ID" = "COMPONENT"."ID"
                   AND "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID"
                  LEFT JOIN "ANALYSIS"
                    ON "ANALYSIS"."COMPONENT_ID" = "COMPONENT"."ID"
                   AND "ANALYSIS"."VULNERABILITY_ID" = "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID"
                 WHERE "FINDINGATTRIBUTION"."ATTRIBUTED_ON" >= :sinceAttributedOn
                   AND %s
                """.formatted(projectIdCondition));
        query.setNamedParameters(queryParams);
        try {
            return List.copyOf(query.executeResultList(NewFinding.class));
        } finally {
            query.closeAll();
        }
    }

    public record NewPolicyViolation(
            long projectId,
            long componentId,
            long policyConditionId,
            Enum<?> violationType,
            Date timestamp,
            Enum<?> analysisState,
            Boolean isSuppressed) {
    }

    private List<NewPolicyViolation> getNewPolicyViolationsSince(
            final QueryManager qm,
            final Collection<Long> projectIds,
            final Date sinceAttributedOn) {
        final Query<PolicyViolation> query = qm.getPersistenceManager().newQuery(PolicyViolation.class);
        query.setFilter(":projectIds.contains(project.id) && timestamp > :sinceAttributedOn");
        query.setNamedParameters(Map.ofEntries(
                Map.entry("projectIds", projectIds),
                Map.entry("sinceAttributedOn", sinceAttributedOn)));
        query.setResult("""
                project.id, component.id, policyCondition.id, type, timestamp, \
                analysis.analysisState, analysis.suppressed""");
        try {
            return List.copyOf(query.executeResultList(NewPolicyViolation.class));
        } finally {
            query.closeAll();
        }
    }

}
