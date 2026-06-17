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

import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.fasterxml.uuid.Generators;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.Timestamps;
import dev.cel.runtime.CelRuntime;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject.ProjectSummaryEntry;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject.ProjectViolationsEntry;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyCondition;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ScheduledNotificationDao;
import org.dependencytrack.persistence.jdbi.ScheduledNotificationDao.NewFinding;
import org.dependencytrack.persistence.jdbi.ScheduledNotificationDao.NewPolicyViolation;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationRuleArg;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_ID;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_RULE_NAME;
import static org.dependencytrack.notification.api.NotificationFactory.createNewPolicyViolationsSummaryNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerabilitiesSummaryNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "process-scheduled-notification-rule", defaultTaskQueue = "notifications")
public final class ProcessScheduledNotificationRuleActivity
        implements Activity<ProcessScheduledNotificationRuleArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessScheduledNotificationRuleActivity.class);

    private final DexEngine dexEngine;
    private final FileStorage fileStorage;
    private final int largeNotificationThresholdBytes;

    public ProcessScheduledNotificationRuleActivity(
            DexEngine dexEngine,
            FileStorage fileStorage,
            int largeNotificationThresholdBytes) {
        this.dexEngine = requireNonNull(dexEngine);
        this.fileStorage = requireNonNull(fileStorage);
        this.largeNotificationThresholdBytes = largeNotificationThresholdBytes;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable ProcessScheduledNotificationRuleArg arg) {
        if (arg == null || arg.getRuleName().isBlank()) {
            throw new TerminalApplicationFailureException("No rule name provided");
        }

        final NotificationRule rule = withJdbiHandle(
                handle -> new ScheduledNotificationDao(handle)
                        .getScheduledNotificationRuleByName(arg.getRuleName()));
        if (rule == null) {
            throw new TerminalApplicationFailureException(
                    "Rule with name %s not found".formatted(arg.getRuleName()));
        }

        try (var _ = MDC.putCloseable(MDC_NOTIFICATION_RULE_NAME, rule.getName())) {
            processRule(rule);
        }

        return null;
    }

    private void processRule(NotificationRule rule) {
        final Instant processingStartedAt = Instant.now();

        final Set<Long> projectIds = withJdbiHandle(handle -> {
            final var dao = new ScheduledNotificationDao(handle);
            if (!dao.hasProjectsConfigured(rule.getId())) {
                return null;
            }

            return dao.getApplicableProjectIds(rule.getId(), rule.isNotifyChildren());
        });
        if (projectIds == null) {
            LOGGER.warn("Rule has no projects configured; advancing schedule");
            advanceSchedule(rule, processingStartedAt);
            return;
        }
        if (projectIds.isEmpty()) {
            LOGGER.warn("All projects configured for rule are inactive; advancing schedule");
            advanceSchedule(rule, processingStartedAt);
            return;
        }

        final Set<NotificationGroup> notifyOn = rule.getNotifyOn();
        if (notifyOn == null || notifyOn.isEmpty()) {
            LOGGER.warn("Rule has no notification groups configured; advancing schedule");
            advanceSchedule(rule, processingStartedAt);
            return;
        }

        for (final NotificationGroup group : notifyOn) {
            if (group != NotificationGroup.NEW_VULNERABILITIES_SUMMARY
                    && group != NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY) {
                LOGGER.warn("Group '{}' is not supported for scheduled dispatch", group);
                continue;
            }

            final String notificationId = createDeterministicNotificationId(
                    rule.getName(), group, rule.getScheduleLastTriggeredAt());

            final Notification notification = withJdbiHandle(handle -> {
                final var scheduledDao = new ScheduledNotificationDao(handle);
                final var subjectDao = handle.attach(NotificationSubjectDao.class);

                return switch (group) {
                    case NEW_VULNERABILITIES_SUMMARY -> createNewVulnerabilitiesNotification(
                            notificationId, scheduledDao, subjectDao, rule, projectIds, processingStartedAt);
                    case NEW_POLICY_VIOLATIONS_SUMMARY -> createNewPolicyViolationsNotification(
                            notificationId, scheduledDao, subjectDao, rule, projectIds, processingStartedAt);
                    default -> throw new TerminalApplicationFailureException("Unexpected group: " + group);
                };
            });

            if (notification != null && evaluateFilterExpression(rule, notification, group)) {
                dispatchNotification(notification, rule.getName());
            }
        }

        advanceSchedule(rule, processingStartedAt);
    }

    private void advanceSchedule(NotificationRule rule, Instant lastTriggeredAt) {
        try {
            final Schedule schedule = Schedule.create(rule.getScheduleCron());
            final Instant nextTriggerAt = schedule.next(Date.from(lastTriggeredAt)).toInstant();
            useJdbiTransaction(
                    handle -> new ScheduledNotificationDao(handle)
                            .updateRuleLastTriggered(rule.getId(), lastTriggeredAt, nextTriggerAt));
        } catch (InvalidExpressionException e) {
            LOGGER.error("Invalid cron expression: '{}'", rule.getScheduleCron(), e);
        }
    }

    private @Nullable Notification createNewVulnerabilitiesNotification(
            String notificationId,
            ScheduledNotificationDao dao,
            NotificationSubjectDao subjectDao,
            NotificationRule rule,
            Set<Long> projectIds,
            Instant processingStartedAt) {
        final Instant sinceAttributedOn =
                rule.getScheduleLastTriggeredAt() != null
                        ? rule.getScheduleLastTriggeredAt().toInstant()
                        : Instant.EPOCH;
        final List<NewFinding> newFindings = dao.getNewFindingsSince(
                projectIds, sinceAttributedOn, processingStartedAt);
        if (newFindings.isEmpty() && Boolean.TRUE.equals(rule.isScheduleSkipUnchanged())) {
            LOGGER.info("No new findings since rule was last processed");
            return null;
        }

        final var findingProjectIds = new HashSet<Long>();
        final var findingComponentIds = new HashSet<Long>();
        final var findingKeys = new HashSet<FindingKey>(newFindings.size());
        for (final NewFinding newFinding : newFindings) {
            findingProjectIds.add(newFinding.projectId());
            findingComponentIds.add(newFinding.componentId());
            findingKeys.add(new FindingKey(newFinding.componentId(), newFinding.vulnerabilityId()));
        }

        final Map<Long, Project> projectById = subjectDao.getProjectsById(findingProjectIds);
        final Map<Long, Component> componentById = subjectDao.getComponentsById(findingComponentIds);
        final Map<FindingKey, Vulnerability> vulnByFindingKey = subjectDao.getVulnsByFindingKey(findingKeys);

        final var findingsByProjectId = new HashMap<Long, List<NewVulnerabilitiesSummarySubject.Finding>>(projectById.size());
        for (final NewFinding newFinding : newFindings) {
            final Project project = projectById.get(newFinding.projectId());
            final Component component = componentById.get(newFinding.componentId());
            final Vulnerability vuln = vulnByFindingKey.get(
                    new FindingKey(newFinding.componentId(), newFinding.vulnerabilityId()));
            if (project == null || component == null || vuln == null) {
                continue;
            }

            final var protoFinding =
                    NewVulnerabilitiesSummarySubject.Finding.newBuilder()
                            .setComponent(component)
                            .setVulnerability(vuln)
                            .setSuppressed(newFinding.suppressed());
            if (newFinding.analyzerIdentity() != null) {
                protoFinding.setAnalyzerIdentity(newFinding.analyzerIdentity());
            }
            if (newFinding.attributedOn() != null) {
                protoFinding.setAttributedOn(Timestamps.fromMillis(newFinding.attributedOn().toEpochMilli()));
            }
            if (newFinding.referenceUrl() != null) {
                protoFinding.setReferenceUrl(newFinding.referenceUrl());
            }
            if (newFinding.analysisState() != null) {
                protoFinding.setAnalysisState(newFinding.analysisState());
            }

            findingsByProjectId
                    .computeIfAbsent(newFinding.projectId(), k -> new ArrayList<>())
                    .add(protoFinding.build());
        }

        int newVulnCount = 0;
        int suppressedCount = 0;
        int totalCount = 0;

        final var countBySeverity = new HashMap<String, Integer>();
        final var componentIdsSeen = new HashSet<Long>();

        for (final NewFinding newFinding : newFindings) {
            componentIdsSeen.add(newFinding.componentId());
            totalCount++;

            if (newFinding.suppressed()) {
                suppressedCount++;
            } else {
                final Vulnerability vuln = vulnByFindingKey.get(
                        new FindingKey(newFinding.componentId(), newFinding.vulnerabilityId()));
                if (vuln != null && vuln.hasSeverity()) {
                    countBySeverity.merge(vuln.getSeverity(), 1, Integer::sum);
                }
                newVulnCount++;
            }
        }

        final var overview = NewVulnerabilitiesSummarySubject.Overview.newBuilder()
                .setAffectedProjectsCount(findingsByProjectId.size())
                .setAffectedComponentsCount(componentIdsSeen.size())
                .setNewVulnerabilitiesCount(newVulnCount)
                .putAllNewVulnerabilitiesCountBySeverity(countBySeverity)
                .setSuppressedNewVulnerabilitiesCount(suppressedCount)
                .setTotalNewVulnerabilitiesCount(totalCount)
                .build();

        // Build per-project summaries and findings entries.
        final var subjectBuilder =
                NewVulnerabilitiesSummarySubject.newBuilder()
                        .setOverview(overview);

        for (final var entry : findingsByProjectId.entrySet()) {
            final Long projectId = entry.getKey();
            final List<NewVulnerabilitiesSummarySubject.Finding> projectFindings = entry.getValue();

            final Project project = projectById.get(projectId);
            if (project == null) {
                continue;
            }

            final var newBySeverity = new HashMap<String, Integer>();
            final var suppressedBySeverity = new HashMap<String, Integer>();
            final var totalBySeverity = new HashMap<String, Integer>();

            for (final NewVulnerabilitiesSummarySubject.Finding projectFinding : projectFindings) {
                final String severity = projectFinding.getVulnerability().getSeverity();

                if (!severity.isEmpty()) {
                    totalBySeverity.merge(severity, 1, Integer::sum);
                    if (projectFinding.getSuppressed()) {
                        suppressedBySeverity.merge(severity, 1, Integer::sum);
                    } else {
                        newBySeverity.merge(severity, 1, Integer::sum);
                    }
                }
            }

            subjectBuilder.addProjectSummaries(
                    NewVulnerabilitiesSummarySubject.ProjectSummaryEntry.newBuilder()
                            .setProject(project)
                            .putAllNewVulnerabilitiesCountBySeverity(newBySeverity)
                            .putAllSuppressedNewVulnerabilitiesCountBySeverity(suppressedBySeverity)
                            .putAllTotalNewVulnerabilitiesCountBySeverity(totalBySeverity));

            subjectBuilder.addFindingsByProject(
                    NewVulnerabilitiesSummarySubject.ProjectFindingsEntry.newBuilder()
                            .setProject(project)
                            .addAllFindings(entry.getValue()));
        }

        if (rule.getScheduleLastTriggeredAt() != null) {
            subjectBuilder.setSince(Timestamps.fromDate(rule.getScheduleLastTriggeredAt()));
        }

        return createNewVulnerabilitiesSummaryNotification(notificationId, subjectBuilder.build());
    }

    private @Nullable Notification createNewPolicyViolationsNotification(
            String notificationId,
            ScheduledNotificationDao dao,
            NotificationSubjectDao subjectDao,
            NotificationRule rule,
            Set<Long> projectIds,
            Instant processingStartedAt) {
        final Instant sinceTimestamp =
                rule.getScheduleLastTriggeredAt() != null
                        ? rule.getScheduleLastTriggeredAt().toInstant()
                        : Instant.EPOCH;
        final List<NewPolicyViolation> violations = dao.getNewPolicyViolationsSince(
                projectIds, sinceTimestamp, processingStartedAt);
        if (violations.isEmpty() && Boolean.TRUE.equals(rule.isScheduleSkipUnchanged())) {
            LOGGER.info("No new policy violations since rule was last processed");
            return null;
        }

        final var violationProjectIds = new HashSet<Long>();
        final var violationComponentIds = new HashSet<Long>();
        final var violationPolicyConditionIds = new HashSet<Long>();
        for (final NewPolicyViolation violation : violations) {
            violationProjectIds.add(violation.projectId());
            violationComponentIds.add(violation.componentId());
            violationPolicyConditionIds.add(violation.policyConditionId());
        }

        final Map<Long, Project> projectById = subjectDao.getProjectsById(violationProjectIds);
        final Map<Long, Component> componentById = subjectDao.getComponentsById(violationComponentIds);
        final Map<Long, PolicyCondition> conditionById = subjectDao.getPolicyConditionsById(violationPolicyConditionIds);

        final var violationsByProjectId = new HashMap<Long, List<NewPolicyViolationsSummarySubject.Violation>>(projectById.size());
        for (final NewPolicyViolation violation : violations) {
            final Project project = projectById.get(violation.projectId());
            final Component component = componentById.get(violation.componentId());
            final PolicyCondition condition = conditionById.get(violation.policyConditionId());
            if (project == null || component == null || condition == null) {
                continue;
            }

            final var entryBuilder =
                    NewPolicyViolationsSummarySubject.Violation.newBuilder()
                            .setUuid(violation.uuid().toString())
                            .setComponent(component)
                            .setPolicyCondition(condition)
                            .setSuppressed(violation.suppressed());
            if (violation.violationType() != null) {
                entryBuilder.setType(violation.violationType());
            }
            if (violation.timestamp() != null) {
                entryBuilder.setTimestamp(Timestamps.fromMillis(violation.timestamp().toEpochMilli()));
            }
            if (violation.analysisState() != null) {
                entryBuilder.setAnalysisState(violation.analysisState());
            }

            violationsByProjectId
                    .computeIfAbsent(violation.projectId(), k -> new ArrayList<>())
                    .add(entryBuilder.build());
        }

        int newViolationsCount = 0;
        int suppressedCount = 0;
        int totalCount = 0;

        final var countByType = new HashMap<String, Integer>();
        final var componentIdsSeen = new HashSet<Long>();

        for (final NewPolicyViolation violation : violations) {
            componentIdsSeen.add(violation.componentId());
            totalCount++;

            if (violation.suppressed()) {
                suppressedCount++;
            } else {
                if (violation.violationType() != null) {
                    countByType.merge(violation.violationType(), 1, Integer::sum);
                }
                newViolationsCount++;
            }
        }

        final var overview =
                NewPolicyViolationsSummarySubject.Overview.newBuilder()
                        .setAffectedProjectsCount(violationsByProjectId.size())
                        .setAffectedComponentsCount(componentIdsSeen.size())
                        .setNewViolationsCount(newViolationsCount)
                        .putAllNewViolationsCountByType(countByType)
                        .setSuppressedNewViolationsCount(suppressedCount)
                        .setTotalNewViolationsCount(totalCount)
                        .build();

        final var subjectBuilder =
                NewPolicyViolationsSummarySubject.newBuilder()
                        .setOverview(overview);

        for (final var entry : violationsByProjectId.entrySet()) {
            final Long projectId = entry.getKey();
            final List<NewPolicyViolationsSummarySubject.Violation> projectViolations = entry.getValue();

            final Project project = projectById.get(projectId);
            if (project == null) {
                continue;
            }

            final var newByType = new HashMap<String, Integer>();
            final var suppressedByType = new HashMap<String, Integer>();
            final var totalByType = new HashMap<String, Integer>();

            for (final NewPolicyViolationsSummarySubject.Violation projectViolation : projectViolations) {
                final String type = projectViolation.getType();

                if (!type.isEmpty()) {
                    totalByType.merge(type, 1, Integer::sum);
                    if (projectViolation.getSuppressed()) {
                        suppressedByType.merge(type, 1, Integer::sum);
                    } else {
                        newByType.merge(type, 1, Integer::sum);
                    }
                }
            }

            subjectBuilder.addProjectSummaries(
                    ProjectSummaryEntry.newBuilder()
                            .setProject(project)
                            .putAllNewViolationsCountByType(newByType)
                            .putAllSuppressedNewViolationsCountByType(suppressedByType)
                            .putAllTotalNewViolationsCountByType(totalByType));

            subjectBuilder.addViolationsByProject(
                    ProjectViolationsEntry.newBuilder()
                            .setProject(project)
                            .addAllViolations(entry.getValue()));
        }

        if (rule.getScheduleLastTriggeredAt() != null) {
            subjectBuilder.setSince(Timestamps.fromDate(rule.getScheduleLastTriggeredAt()));
        }

        return createNewPolicyViolationsSummaryNotification(notificationId, subjectBuilder.build());
    }

    private boolean evaluateFilterExpression(
            NotificationRule rule,
            Notification notification,
            NotificationGroup group) {
        final String filterExpression = rule.getFilterExpression();
        if (filterExpression == null || filterExpression.isBlank()) {
            return true;
        }

        final Object subject = unpackSubject(notification, group);
        final var expressionEnv = NotificationFilterExpressionEnv.getInstance();

        try {
            final CelRuntime.Program program = expressionEnv.compile(filterExpression);
            final boolean result = expressionEnv.evaluate(program, notification, subject);
            LOGGER.debug("Filter expression evaluated to {}", result);
            return result;
        } catch (Exception e) {
            LOGGER.warn("Failed to evaluate filter expression for rule {}; Failing open", rule.getName(), e);
            return true;
        }
    }

    private @Nullable Object unpackSubject(Notification notification, NotificationGroup group) {
        if (!notification.hasSubject()) {
            return null;
        }

        try {
            return switch (group) {
                case NEW_VULNERABILITIES_SUMMARY -> notification.getSubject().unpack(
                        NewVulnerabilitiesSummarySubject.class);
                case NEW_POLICY_VIOLATIONS_SUMMARY -> notification.getSubject().unpack(
                        NewPolicyViolationsSummarySubject.class);
                default -> null;
            };
        } catch (InvalidProtocolBufferException e) {
            LOGGER.warn("Failed to unpack notification subject", e);
            return null;
        }
    }

    private void dispatchNotification(Notification notification, String ruleName) {
        final String workflowInstanceId = "publish-scheduled-notification:" + notification.getId();

        final var workflowArgBuilder = PublishNotificationWorkflowArg.newBuilder()
                .setNotificationId(notification.getId())
                .addNotificationRuleNames(ruleName);

        try (var _ = MDC.putCloseable(MDC_NOTIFICATION_ID, notification.getId())) {
            if (notification.getSerializedSize() > largeNotificationThresholdBytes) {
                LOGGER.warn(
                        "Notification size {}b exceeds threshold of {}b; offloading to file storage",
                        notification.getSerializedSize(), largeNotificationThresholdBytes);
                try {
                    final FileMetadata fileMetadata = fileStorage.store(
                            "notifications/%s.proto".formatted(notification.getId()),
                            "application/protobuf",
                            new ByteArrayInputStream(notification.toByteArray()));
                    workflowArgBuilder.setNotificationFileMetadata(fileMetadata);
                } catch (IOException e) {
                    throw new UncheckedIOException("Failed to store notification file", e);
                }
            } else {
                workflowArgBuilder.setNotification(notification);
            }

            final UUID runId = dexEngine.createRun(
                    new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                            .withWorkflowInstanceId(workflowInstanceId)
                            .withArgument(workflowArgBuilder.build()));
            if (runId != null) {
                LOGGER.debug("Created publish workflow run {}", runId);
            } else {
                LOGGER.warn("""
                        A publish workflow run is already in progress for this notification; \
                        No new run created to avoid duplicates""");
            }
        }
    }

    private static String createDeterministicNotificationId(
            String ruleName,
            NotificationGroup group,
            @Nullable Date lastTriggeredAt) {
        final long timestampMillis = lastTriggeredAt != null
                ? lastTriggeredAt.getTime()
                : 0;

        final String randomSeedInput = "%s:%s:%d".formatted(ruleName, group, timestampMillis);
        final long randomSeed = UUID
                .nameUUIDFromBytes(randomSeedInput.getBytes(StandardCharsets.UTF_8))
                .getMostSignificantBits();

        return Generators
                .timeBasedEpochRandomGenerator(new Random(randomSeed))
                .construct(timestampMillis)
                .toString();
    }

}
