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

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.Subscriber;
import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.publisher.PublishContext;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.BomValidationFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.ScheduledNotificationSubject;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_KEY;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY;
import static org.dependencytrack.util.PersistenceUtil.isPersistent;

public class NotificationRouter implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NotificationRouter.class);

    public void inform(final Notification notification) {
        final PublishContext ctx = PublishContext.from(notification);

        for (final NotificationRule rule : resolveRules(ctx, notification)) {
            final PublishContext ruleCtx = ctx.withRule(rule);

            // Not all publishers need configuration (i.e. ConsolePublisher)
            JsonObject config = Json.createObjectBuilder().build();
            if (rule.getPublisherConfig() != null) {
                try (StringReader stringReader = new StringReader(rule.getPublisherConfig());
                     final JsonReader jsonReader = Json.createReader(stringReader)) {
                    config = jsonReader.readObject();
                } catch (Exception e) {
                    LOGGER.error("An error occurred while preparing the configuration for the notification publisher (%s)".formatted(ruleCtx), e);
                }
            }
            try {
                NotificationPublisher notificationPublisher = rule.getPublisher();
                final Class<?> publisherClass = Class.forName(notificationPublisher.getPublisherClass());
                if (Publisher.class.isAssignableFrom(publisherClass)) {
                    final Publisher publisher = (Publisher) publisherClass.getDeclaredConstructor().newInstance();
                    JsonObject notificationPublisherConfig = Json.createObjectBuilder()
                            .add(CONFIG_TEMPLATE_MIME_TYPE_KEY, notificationPublisher.getTemplateMimeType())
                            .add(CONFIG_TEMPLATE_KEY, notificationPublisher.getTemplate())
                            .addAll(Json.createObjectBuilder(config))
                            .build();
                    publisher.inform(ruleCtx, restrictNotificationToRuleProjects(notification, rule), notificationPublisherConfig);
                } else {
                    LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName() + " (%s)".formatted(ruleCtx));
                }
            } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException |
                     InvocationTargetException | IllegalAccessException e) {
                LOGGER.error("An error occurred while instantiating a notification publisher (%s)".formatted(ruleCtx), e);
            } catch (PublisherException publisherException) {
                LOGGER.error("An error occurred during the publication of the notification (%s)".formatted(ruleCtx), publisherException);
            }
        }
    }

    private Notification restrictNotificationToRuleProjects(final Notification notification, final NotificationRule rule) {
        if (!(notification.getSubject() instanceof final NewVulnerabilityIdentified subject)
                || subject.getAffectedProjects() == null || subject.getAffectedProjects().isEmpty()) {
            return notification;
        }

        final boolean shouldFilterOnRuleProjects = rule.getProjects() != null && !rule.getProjects().isEmpty();
        final boolean shouldFilterOnRuleTags = rule.getTags() != null && !rule.getTags().isEmpty();
        if (!shouldFilterOnRuleProjects && !shouldFilterOnRuleTags) {
            return notification;
        }

        final Predicate<Project> projectFilterPredicate;
        if (shouldFilterOnRuleProjects && shouldFilterOnRuleTags) {
            projectFilterPredicate = matchesAnyProjectOfRule(rule).or(hasAnyTagOfRule(rule));
        } else if (shouldFilterOnRuleProjects) {
            projectFilterPredicate = matchesAnyProjectOfRule(rule);
        } else {
            projectFilterPredicate = hasAnyTagOfRule(rule);
        }

        final Set<Project> filteredAffectedProjects = subject.getAffectedProjects().stream()
                .filter(projectFilterPredicate)
                .collect(Collectors.toSet());
        if (filteredAffectedProjects.size() == subject.getAffectedProjects().size()) {
            return notification;
        }

        final var filteredSubject = new NewVulnerabilityIdentified(
                subject.getVulnerability(),
                subject.getComponent(),
                filteredAffectedProjects,
                subject.getVulnerabilityAnalysisLevel()
        );

        return new Notification()
                .group(notification.getGroup())
                .scope(notification.getScope())
                .level(notification.getLevel())
                .title(notification.getTitle())
                .content(notification.getContent())
                .timestamp(notification.getTimestamp())
                .subject(filteredSubject);
    }

    private Predicate<Project> matchesAnyProjectOfRule(final NotificationRule rule) {
        requireNonNull(rule.getProjects());

        return project -> rule.getProjects().stream()
                .map(Project::getUuid)
                .anyMatch(project.getUuid()::equals);
    }

    private Predicate<Project> hasAnyTagOfRule(final NotificationRule rule) {
        requireNonNull(rule.getTags());

        return project -> {
            if (project.getTags() == null || project.getTags().isEmpty()) {
                return false;
            }

            final Set<String> projectTagNames = project.getTags().stream()
                    .map(Tag::getName)
                    .collect(Collectors.toSet());

            return rule.getTags().stream()
                    .map(Tag::getName)
                    .anyMatch(projectTagNames::contains);
        };
    }

    List<NotificationRule> resolveRules(final PublishContext ctx, final Notification notification) {
        final List<NotificationRule> rules = new ArrayList<>();
        if (notification == null || notification.getScope() == null || notification.getGroup() == null || notification.getLevel() == null) {
            LOGGER.debug("Mandatory fields of notification are missing; Unable to resolve rules (%s)".formatted(ctx));
            return rules;
        }

        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            // Scheduled notifications are created based on specific rules already,
            // and require no more rule resolution.
            if (notification.getSubject() instanceof final ScheduledNotificationSubject subject) {
                pm.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
                final var rule = qm.getObjectById(NotificationRule.class, subject.getRuleId());
                if (rule == null) {
                    LOGGER.warn("Notification rule with ID %d does not exist".formatted(subject.getRuleId()));
                    return rules;
                }

                rules.add(pm.detachCopy(rule));
                return rules;
            }

            final Query<NotificationRule> query = pm.newQuery(NotificationRule.class);
            pm.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
            final StringBuilder sb = new StringBuilder();

            final NotificationLevel level = notification.getLevel();
            if (NotificationLevel.INFORMATIONAL == level) {
                sb.append("notificationLevel == 'INFORMATIONAL' && ");
            } else if (NotificationLevel.WARNING == level) {
                sb.append("(notificationLevel == 'WARNING' || notificationLevel == 'INFORMATIONAL') && ");
            } else if (NotificationLevel.ERROR == level) {
                sb.append("(notificationLevel == 'INFORMATIONAL' || notificationLevel == 'WARNING' || notificationLevel == 'ERROR') && ");
            }

            sb.append("enabled == true && triggerType == 'EVENT' && scope == :scope"); //todo: improve this - this only works for testing
            query.setFilter(sb.toString());
            query.setParameters(NotificationScope.valueOf(notification.getScope()));
            final List<NotificationRule> result = query.executeList();
            pm.detachCopyAll(result);
            LOGGER.debug("Matched %d notification rules (%s)".formatted(result.size(), ctx));

            if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getComponent().getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final NewVulnerableDependency subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getComponent().getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final BomConsumedOrProcessed subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final BomProcessingFailed subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final BomValidationFailed subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final VexConsumedOrProcessed subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final PolicyViolationIdentified subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final AnalysisDecisionChange subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final ViolationAnalysisDecisionChange subject) {
                limitToProject(qm, ctx, rules, result, notification, subject.getComponent().getProject());
            } else {
                for (final NotificationRule rule : result) {
                    if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                        rules.add(rule);
                    }
                }
            }
        }
        return rules;
    }

    /**
     * if the rule specified one or more projects as targets, reduce the execution
     * of the notification down to those projects that the rule matches and which
     * also match projects affected by the vulnerability.
     */
    private void limitToProject(
            final QueryManager qm,
            final PublishContext ctx,
            final List<NotificationRule> applicableRules,
            final List<NotificationRule> rules,
            final Notification notification,
            Project limitToProject
    ) {
        requireNonNull(limitToProject, "limitToProject must not be null");

        for (final NotificationRule rule : rules) {
            final PublishContext ruleCtx = ctx.withRule(rule);

            if (!rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                continue;
            }

            final boolean isLimitedToProjects = rule.getProjects() != null && !rule.getProjects().isEmpty();
            final boolean isLimitedToTags = rule.getTags() != null && !rule.getTags().isEmpty();
            if (!isLimitedToProjects && !isLimitedToTags) {
                LOGGER.debug("Rule is not limited to projects or tags; Rule is applicable (%s)".formatted(ruleCtx));
                applicableRules.add(rule);
                continue;
            }

            if (isLimitedToTags) {
                // Project must be in persistent state in order for tag evaluation to work:
                //   * tags field must be loaded, which oftentimes it won't be at this point.
                //   * Traversing project hierarchies (if isNotifyChildren is enabled) doesn't work on detached objects.
                if (!isPersistent(limitToProject)) {
                    LOGGER.debug("Refreshing project %s from datastore".formatted(limitToProject.getUuid()));

                    final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
                    query.setFilter("uuid == :uuid");
                    query.setParameters(limitToProject.getUuid());
                    query.getFetchPlan().addGroup(Project.FetchGroup.PROJECT_TAGS.name());

                    final Project persistentProject;
                    try {
                        persistentProject = query.executeUnique();
                    } finally {
                        query.closeAll();
                    }

                    if (persistentProject == null) {
                        throw new IllegalStateException("""
                                Project %s had to be refreshed from the datastore in order for tags \
                                to be loaded, but the project no longer exists\
                                """.formatted(limitToProject.getUuid()));
                    }

                    limitToProject = persistentProject;
                }

                final Predicate<Project> tagMatchPredicate = project -> project.isActive()
                        && project.getTags() != null
                        && project.getTags().stream().anyMatch(rule.getTags()::contains);

                if (tagMatchPredicate.test(limitToProject)) {
                    LOGGER.debug("""
                            Project %s is tagged with any of the "limit to" tags; \
                            Rule is applicable (%s)""".formatted(limitToProject.getUuid(), ruleCtx));
                    applicableRules.add(rule);
                    continue;
                } else if (rule.isNotifyChildren() && isChildOfProjectMatching(limitToProject, tagMatchPredicate)) {
                    LOGGER.debug("""
                            Project %s is child of a project tagged with any of the "limit to" tags; \
                            Rule is applicable (%s)""".formatted(limitToProject.getUuid(), ruleCtx));
                    applicableRules.add(rule);
                    continue;
                }
            } else {
                LOGGER.debug("Rule is not limited to tags (%s)".formatted(ruleCtx));
            }

            if (isLimitedToProjects) {
                var matched = false;
                for (final Project project : rule.getProjects()) {
                    if (project.getUuid().equals(limitToProject.getUuid())) {
                        LOGGER.debug("Project %s is part of the \"limit to\" list of the rule; Rule is applicable (%s)"
                                .formatted(limitToProject.getUuid(), ruleCtx));
                        matched = true;
                        break;
                    } else if (rule.isNotifyChildren()) {
                        final boolean isChildOfLimitToProject = checkIfChildrenAreAffected(project, limitToProject.getUuid());
                        if (isChildOfLimitToProject) {
                            LOGGER.debug("Project %s is child of \"limit to\" project %s; Rule is applicable (%s)"
                                    .formatted(limitToProject.getUuid(), project.getUuid(), ruleCtx));
                            matched = true;
                            break;
                        } else {
                            LOGGER.debug("Project %s is not a child of \"limit to\" project %s (%s)"
                                    .formatted(limitToProject.getUuid(), project.getUuid(), ruleCtx));
                        }
                    }
                }

                if (matched) {
                    applicableRules.add(rule);
                } else {
                    LOGGER.debug("Project %s is not part of the \"limit to\" list of the rule; Rule is not applicable (%s)"
                            .formatted(limitToProject.getUuid(), ruleCtx));
                }
            } else {
                LOGGER.debug("Rule is not limited to projects (%s)".formatted(ruleCtx));
            }
        }

        LOGGER.debug("Applicable rules: %s (%s)"
                .formatted(applicableRules.stream().map(NotificationRule::getName).collect(Collectors.joining(", ")), ctx));
    }

    private boolean checkIfChildrenAreAffected(Project parent, UUID uuid) {
        // TODO: Making this a recursive SQL query would be a lot more efficient.

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

    private boolean isChildOfProjectMatching(final Project childProject, final Predicate<Project> matchFunction) {
        // TODO: Making this a recursive SQL query would be a lot more efficient.

        Project parent = childProject.getParent();
        while (parent != null) {
            if (matchFunction.test(parent)) {
                return true;
            }

            parent = parent.getParent();
        }

        return false;
    }

}
