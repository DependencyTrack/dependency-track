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

import dev.cel.runtime.CelRuntime;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityRetractedSubject;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_GROUP;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_ID;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_LEVEL;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_SCOPE;
import static org.dependencytrack.notification.NotificationModelConverter.convert;

/**
 * @since 5.0.0
 */
final class NotificationRouter {

    record Result(Notification notification, Set<String> ruleNames) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRouter.class.getName());

    private final Handle jdbiHandle;
    private final Timer ruleQueryLatency;
    private final Timer ruleFilterLatency;
    private final MeterProvider<Counter> rulesMatchedCounter;

    NotificationRouter(
            Handle jdbiHandle,
            MeterRegistry meterRegistry) {
        this.jdbiHandle = requireNonNull(jdbiHandle, "jdbiHandle must not be null");
        requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.ruleQueryLatency = Timer
                .builder("dt.notification.router.rule.query.latency")
                .description("Latency of applicable notification rule queries")
                .register(meterRegistry);
        this.ruleFilterLatency = Timer
                .builder("dt.notification.router.rule.filter.latency")
                .description("Latency of applicable notification rule filtering")
                .register(meterRegistry);
        this.rulesMatchedCounter = Counter
                .builder("dt.notification.router.rules.matched")
                .description("Number of matched notification rules")
                .withRegistry(meterRegistry);
    }

    List<Result> route(Collection<Notification> notifications) {
        requireNonNull(notifications, "notifications must not be null");
        if (notifications.isEmpty()) {
            return Collections.emptyList();
        }

        final Timer.Sample ruleQueryLatencySample = Timer.start();
        final Map<Notification, List<RuleQueryResult>> rulesByNotification;
        try {
            rulesByNotification = queryRules(notifications);
        } finally {
            ruleQueryLatencySample.stop(ruleQueryLatency);
        }

        if (rulesByNotification.isEmpty()) {
            LOGGER.debug("None of the provided {} notifications have any matching rules", notifications.size());
            return Collections.emptyList();
        }

        final var results = new ArrayList<Result>(rulesByNotification.size());

        for (final Map.Entry<Notification, List<RuleQueryResult>> entry : rulesByNotification.entrySet()) {
            final Notification notification = entry.getKey();
            final List<RuleQueryResult> rules = entry.getValue();

            try (var ignoredMdcScope = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_NOTIFICATION_ID, notification.getId()),
                    Map.entry(MDC_NOTIFICATION_SCOPE, convert(notification.getScope()).name()),
                    Map.entry(MDC_NOTIFICATION_GROUP, convert(notification.getGroup()).name()),
                    Map.entry(MDC_NOTIFICATION_LEVEL, convert(notification.getLevel()).name())))) {
                final Timer.Sample ruleFilterLatencySample = Timer.start();
                final List<RuleQueryResult> applicableRules;
                try {
                    applicableRules = maybeFilterRules(notification, rules);
                } finally {
                    ruleFilterLatencySample.stop(ruleFilterLatency);
                }

                final var applicableRuleNames = new HashSet<String>(applicableRules.size());
                for (final RuleQueryResult rule : applicableRules) {
                    rulesMatchedCounter.withTag("ruleName", rule.name()).increment();
                    applicableRuleNames.add(rule.name());
                }

                if (!applicableRuleNames.isEmpty()) {
                    results.add(new Result(notification, applicableRuleNames));
                }
            }
        }

        return results;
    }

    public record RuleQueryResult(
            int notificationIndex,
            long id,
            String name,
            boolean isNotifyChildProjects,
            @Nullable Set<String> limitToProjectUuids,
            @Nullable Set<String> limitToTagNames,
            @Nullable String filterExpression) {

        private boolean isLimitedToProjects() {
            return limitToProjectUuids != null && !limitToProjectUuids.isEmpty();
        }

        private boolean isLimitedToTags() {
            return limitToTagNames != null && !limitToTagNames.isEmpty();
        }

        private boolean hasFilterExpression() {
            return filterExpression != null && !filterExpression.isBlank();
        }

    }

    private Map<Notification, List<RuleQueryResult>> queryRules(Collection<Notification> notifications) {
        // Copy notifications into a list so they're accessible by index.
        final var notificationsList = List.copyOf(notifications);

        final var indexes = new int[notificationsList.size()];
        final var scopes = new NotificationScope[notificationsList.size()];
        final var groups = new NotificationGroup[notificationsList.size()];
        final var levels = new NotificationLevel[notificationsList.size()];

        for (int i = 0; i < notificationsList.size(); i++) {
            final Notification notification = notificationsList.get(i);
            indexes[i] = i;
            scopes[i] = convert(notification.getScope());
            groups[i] = convert(notification.getGroup());
            levels[i] = convert(notification.getLevel());
        }

        // Retrieve potentially matching rules for all notifications at once.
        // Keep track of which result was returned for which notification via
        // the notification's index.
        //
        // Note that this can potentially return redundant data, say when all
        // notifications yield the same N results. In such cases it might be
        // more efficient to query the rule IDs first, and then retrieve more
        // rule information separately. We leave that for a future optimisation.
        final Query query = jdbiHandle.createQuery("""
                SELECT t.index AS notification_index
                     , rule."ID"
                     , rule."NAME"
                     , rule."NOTIFY_CHILDREN" AS is_notify_child_projects
                     , (
                         SELECT ARRAY_AGG("PROJECT"."UUID")
                           FROM "NOTIFICATIONRULE_PROJECTS"
                          INNER JOIN "PROJECT"
                             ON "PROJECT"."ID" = "NOTIFICATIONRULE_PROJECTS"."PROJECT_ID"
                          WHERE "NOTIFICATIONRULE_ID" = rule."ID"
                       ) AS limit_to_project_uuids
                     , (
                         SELECT ARRAY_AGG("TAG"."NAME")
                           FROM "NOTIFICATIONRULE_TAGS"
                          INNER JOIN "TAG"
                             ON "TAG"."ID" = "NOTIFICATIONRULE_TAGS"."TAG_ID"
                          WHERE "NOTIFICATIONRULE_ID" = rule."ID"
                       ) AS limit_to_tag_names
                     , rule."FILTER_EXPRESSION"
                  FROM UNNEST(:indexes, :scopes, :levels, :groups)
                    AS t(index, scope, level, "group")
                 INNER JOIN "NOTIFICATIONRULE" AS rule
                    ON rule."SCOPE" = t.scope
                   AND t."group" = ANY(rule."NOTIFY_ON")
                   AND rule."NOTIFICATION_LEVEL" <= t.level
                 WHERE rule."ENABLED"
                   AND rule."TRIGGER_TYPE" = 'EVENT'
                """);

        return query
                // Ensure level is cast to its corresponding enum type in the database.
                // Necessary to support the <= comparison.
                .registerArrayType(NotificationLevel.class, "notification_level")
                .bind("indexes", indexes)
                .bind("scopes", scopes)
                .bind("groups", groups)
                .bind("levels", levels)
                .map(ConstructorMapper.of(RuleQueryResult.class))
                .stream()
                .collect(Collectors.groupingBy(
                        rule -> notificationsList.get(rule.notificationIndex()),
                        Collectors.toList()));
    }

    private List<RuleQueryResult> maybeFilterRules(
            Notification notification,
            List<RuleQueryResult> ruleCandidates) {
        final Object unpackedSubject = unpackSubject(notification);
        final Project projectSubject = getProjectSubject(unpackedSubject);

        final var applicableRules = new ArrayList<RuleQueryResult>(ruleCandidates.size());
        for (final RuleQueryResult rule : ruleCandidates) {
            try (var ignoredMdcRuleName = MDC.putCloseable("notificationRuleName", rule.name())) {
                if (isApplicable(rule, notification, projectSubject, unpackedSubject)) {
                    LOGGER.debug("Rule is applicable");
                    applicableRules.add(rule);
                } else {
                    LOGGER.debug("Rule is not applicable");
                }
            }
        }

        return applicableRules;
    }

    private boolean isApplicable(
            RuleQueryResult rule,
            Notification notification,
            @Nullable Project project,
            @Nullable Object subject) {
        if (!isApplicableByProjectOrTag(rule, project)) {
            return false;
        }

        if (!evaluateFilterExpression(rule, notification, subject)) {
            LOGGER.debug("Notification did not match the rule's filter expression");
            return false;
        }

        return true;
    }

    private boolean isApplicableByProjectOrTag(RuleQueryResult rule, @Nullable Project project) {
        if (!rule.isLimitedToProjects() && !rule.isLimitedToTags()) {
            LOGGER.debug("Rule is not limited to projects or tags");
            return true;
        }

        if (project == null) {
            LOGGER.debug("Notification has no project subject; Skipping project/tag filtering");
            return true;
        }

        if (rule.isLimitedToTags()) {
            LOGGER.debug("Rule is limited to tags: {}", rule.limitToTagNames());

            final String matchedTagName = project.getTagsList().stream()
                    .filter(rule.limitToTagNames()::contains)
                    .findAny()
                    .orElse(null);
            if (matchedTagName != null) {
                LOGGER.debug("Rule matched project on tag {}", matchedTagName);
                return true;
            } else {
                LOGGER.debug("Rule did not match any project tag");
                return false;
            }
        }

        if (rule.isLimitedToProjects()) {
            LOGGER.debug("Rule is limited to projects with UUIDs: {}", rule.limitToProjectUuids());

            if (rule.limitToProjectUuids().contains(project.getUuid())) {
                LOGGER.debug("Rule matched project on UUID: {}", project.getUuid());
                return true;
            } else if (rule.isNotifyChildProjects()) {
                LOGGER.debug("Rule did not match on any project UUID");
                if (isChildOfAnyActiveParent(rule.limitToProjectUuids(), project.getUuid())) {
                    LOGGER.debug("Rule matched parents of project");
                    return true;
                } else {
                    LOGGER.debug("""
                            Rule did not match: Project {} is not a child of any \
                            specified parent projects""", project.getUuid());
                    return false;
                }
            }
        }

        return false;
    }

    private boolean evaluateFilterExpression(
            RuleQueryResult rule,
            Notification notification,
            @Nullable Object subject) {
        final String filterExpression = rule.filterExpression();
        if (filterExpression == null || filterExpression.isBlank()) {
            return true;
        }

        final var expressionEnv = NotificationFilterExpressionEnv.getInstance();

        try {
            final CelRuntime.Program program = expressionEnv.compile(rule.filterExpression());
            final boolean result = expressionEnv.evaluate(program, notification, subject);
            LOGGER.debug("Filter expression evaluated to {}", result);
            return result;
        } catch (Exception e) {
            LOGGER.warn("Failed to evaluate filter expression for rule {}; Failing open", rule.name(), e);
            return true;
        }
    }

    private @Nullable Project getProjectSubject(@Nullable Object subject) {
        return switch (subject) {
            case BomConsumedOrProcessedSubject it -> it.getProject();
            case VulnerabilityRetractedSubject it -> it.getProject();
            case BomProcessingFailedSubject it -> it.getProject();
            case BomValidationFailedSubject it -> it.getProject();
            case NewVulnerabilitySubject it -> it.getProject();
            case NewVulnerableDependencySubject it -> it.getProject();
            case PolicyViolationSubject it -> it.getProject();
            case PolicyViolationAnalysisDecisionChangeSubject it -> it.getProject();
            case VulnerabilityAnalysisDecisionChangeSubject it -> it.getProject();
            case Project it -> it;
            case ProjectVulnAnalysisCompleteSubject it -> it.getProject();
            case VexConsumedOrProcessedSubject it -> it.getProject();
            case null, default -> null;
        };
    }

    private @Nullable Object unpackSubject(Notification notification) {
        if (!notification.hasSubject()) {
            return null;
        }

        try {
            return switch (notification.getGroup()) {
                case GROUP_BOM_CONSUMED, GROUP_BOM_PROCESSED -> notification.getSubject().unpack(
                        BomConsumedOrProcessedSubject.class);
                case GROUP_VULNERABILITY_RETRACTED -> notification.getSubject().unpack(
                        VulnerabilityRetractedSubject.class);
                case GROUP_BOM_PROCESSING_FAILED -> notification.getSubject().unpack(
                        BomProcessingFailedSubject.class);
                case GROUP_BOM_VALIDATION_FAILED -> notification.getSubject().unpack(
                        BomValidationFailedSubject.class);
                case GROUP_NEW_VULNERABILITY -> notification.getSubject().unpack(
                        NewVulnerabilitySubject.class);
                case GROUP_NEW_VULNERABLE_DEPENDENCY -> notification.getSubject().unpack(
                        NewVulnerableDependencySubject.class);
                case GROUP_POLICY_VIOLATION -> notification.getSubject().unpack(
                        PolicyViolationSubject.class);
                case GROUP_PROJECT_AUDIT_CHANGE -> {
                    if (notification.getSubject().is(PolicyViolationAnalysisDecisionChangeSubject.class)) {
                        yield notification.getSubject().unpack(PolicyViolationAnalysisDecisionChangeSubject.class);
                    } else if (notification.getSubject().is(VulnerabilityAnalysisDecisionChangeSubject.class)) {
                        yield notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
                    }
                    throw new IllegalStateException(
                            "Unexpected subject for group %s: %s".formatted(
                                    notification.getGroup(), notification.getSubject().getTypeUrl()));
                }
                case GROUP_PROJECT_CREATED -> notification.getSubject().unpack(Project.class);
                case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> notification.getSubject().unpack(
                        ProjectVulnAnalysisCompleteSubject.class);
                case GROUP_VEX_CONSUMED, GROUP_VEX_PROCESSED -> notification.getSubject().unpack(
                        VexConsumedOrProcessedSubject.class);
                case GROUP_USER_CREATED, GROUP_USER_DELETED -> notification.getSubject().unpack(
                        UserSubject.class);
                default -> null;
            };
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to unpack subject", e);
        }
    }

    private boolean isChildOfAnyActiveParent(Collection<String> parentUuids, String childUuid) {
        final Query query = jdbiHandle.createQuery("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "PROJECT_HIERARCHY" AS hierarchy
                   INNER JOIN "PROJECT" AS parent_project
                      ON parent_project."ID" = hierarchy."PARENT_PROJECT_ID"
                   INNER JOIN "PROJECT" AS child_project
                      ON child_project."ID" = hierarchy."CHILD_PROJECT_ID"
                   WHERE parent_project."UUID" = ANY(CAST(:parentUuids AS UUID[]))
                     AND parent_project."INACTIVE_SINCE" IS NULL
                     AND child_project."UUID" = CAST(:childUuid AS UUID)
                )
                """);

        return query
                .bindArray("parentUuids", String.class, parentUuids)
                .bind("childUuid", childUuid)
                .mapTo(boolean.class)
                .one();
    }

}
