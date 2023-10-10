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
 * Copyright (c) Steve Springett. All Rights Reserved.
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
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class NotificationRouter implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NotificationRouter.class);

    public void inform(final Notification notification) {
        for (final NotificationRule rule: resolveRules(notification)) {

            // Not all publishers need configuration (i.e. ConsolePublisher)
            JsonObject config = Json.createObjectBuilder().build();
            if (rule.getPublisherConfig() != null) {
                try (StringReader stringReader = new StringReader(rule.getPublisherConfig());
                     final JsonReader jsonReader = Json.createReader(stringReader)) {
                    config = jsonReader.readObject();
                } catch (Exception e) {
                    LOGGER.error("An error occurred while preparing the configuration for the notification publisher", e);
                }
            }
            try {
                NotificationPublisher notificationPublisher = rule.getPublisher();
                final Class<?> publisherClass = Class.forName(notificationPublisher.getPublisherClass());
                if (Publisher.class.isAssignableFrom(publisherClass)) {
                    final Publisher publisher = (Publisher)publisherClass.getDeclaredConstructor().newInstance();
                    JsonObject notificationPublisherConfig = Json.createObjectBuilder()
                                                                 .add(Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY, notificationPublisher.getTemplateMimeType())
                                                                 .add(Publisher.CONFIG_TEMPLATE_KEY, notificationPublisher.getTemplate())
                                                                 .addAll(Json.createObjectBuilder(config))
                                                                         .build();
                    if (publisherClass != SendMailPublisher.class || rule.getTeams().isEmpty() || rule.getTeams() == null){
                        publisher.inform(restrictNotificationToRuleProjects(notification, rule), notificationPublisherConfig);
                    } else {
                        ((SendMailPublisher)publisher).inform(restrictNotificationToRuleProjects(notification, rule), notificationPublisherConfig, rule.getTeams());
                    }


                } else {
                    LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName());
                }
            } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | InvocationTargetException | IllegalAccessException e) {
                LOGGER.error("An error occurred while instantiating a notification publisher", e);
            } catch (PublisherException publisherException) {
                LOGGER.error("An error occured during the publication of the notification", publisherException);
            }
        }
    }

    public Notification restrictNotificationToRuleProjects(Notification initialNotification, NotificationRule rule) {
        Notification restrictedNotification = initialNotification;
        if(canRestrictNotificationToRuleProjects(initialNotification, rule)) {
            Set<String> ruleProjectsUuids = rule.getProjects().stream().map(Project::getUuid).map(UUID::toString).collect(Collectors.toSet());
            restrictedNotification = new Notification();
            restrictedNotification.setGroup(initialNotification.getGroup());
            restrictedNotification.setLevel(initialNotification.getLevel());
            restrictedNotification.scope(initialNotification.getScope());
            restrictedNotification.setContent(initialNotification.getContent());
            restrictedNotification.setTitle(initialNotification.getTitle());
            restrictedNotification.setTimestamp(initialNotification.getTimestamp());
            if(initialNotification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
                Set<Project> restrictedProjects = subject.getAffectedProjects().stream().filter(project -> ruleProjectsUuids.contains(project.getUuid().toString())).collect(Collectors.toSet());
                NewVulnerabilityIdentified restrictedSubject = new NewVulnerabilityIdentified(subject.getVulnerability(), subject.getComponent(), restrictedProjects, null);
                restrictedNotification.setSubject(restrictedSubject);
            }
        }
        return restrictedNotification;
    }

    private boolean canRestrictNotificationToRuleProjects(Notification initialNotification, NotificationRule rule) {
        return initialNotification.getSubject() instanceof NewVulnerabilityIdentified &&
                rule.getProjects() != null
                && rule.getProjects().size() > 0;
    }

    List<NotificationRule> resolveRules(final Notification notification) {
        // The notification rules to process for this specific notification
        final List<NotificationRule> rules = new ArrayList<>();

        if (notification == null || notification.getScope() == null || notification.getGroup() == null || notification.getLevel() == null) {
            return rules;
        }
        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
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

            sb.append("enabled == true && scope == :scope"); //todo: improve this - this only works for testing
            query.setFilter(sb.toString());
            query.setParameters(NotificationScope.valueOf(notification.getScope()));
            final List<NotificationRule> result = query.executeList();
            pm.detachCopyAll(result);

            if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
                // If the rule specified one or more projects as targets, reduce the execution
                // of the notification down to those projects that the rule matches and which
                // also match project the component is included in.
                // NOTE: This logic is slightly different from what is implemented in limitToProject()
                for (final NotificationRule rule: result) {
                    if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                        if (rule.getProjects() != null && rule.getProjects().size() > 0
                            && subject.getComponent() != null && subject.getComponent().getProject() != null) {
                            for (final Project project : rule.getProjects()) {
                                if (subject.getComponent().getProject().getUuid().equals(project.getUuid()) || (Boolean.TRUE.equals(rule.isNotifyChildren() && checkIfChildrenAreAffected(project, subject.getComponent().getProject().getUuid())))) {
                                    rules.add(rule);
                                }
                            }
                        } else {
                            rules.add(rule);
                        }
                    }
                }
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final NewVulnerableDependency subject) {
                limitToProject(rules, result, notification, subject.getComponent().getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final BomConsumedOrProcessed subject) {
                limitToProject(rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final BomProcessingFailed subject) {
                limitToProject(rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final VexConsumedOrProcessed subject) {
                limitToProject(rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final PolicyViolationIdentified subject) {
                limitToProject(rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final AnalysisDecisionChange subject) {
                limitToProject(rules, result, notification, subject.getProject());
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() instanceof final ViolationAnalysisDecisionChange subject) {
                limitToProject(rules, result, notification, subject.getComponent().getProject());
            } else {
                for (final NotificationRule rule: result) {
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
     * */
    private void limitToProject(final List<NotificationRule> applicableRules, final List<NotificationRule> rules,
                                final Notification notification, final Project limitToProject) {
        for (final NotificationRule rule: rules) {
            if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                if (rule.getProjects() != null && rule.getProjects().size() > 0) {
                    for (final Project project : rule.getProjects()) {
                        if (project.getUuid().equals(limitToProject.getUuid()) || (Boolean.TRUE.equals(rule.isNotifyChildren()) && checkIfChildrenAreAffected(project, limitToProject.getUuid()))) {
                            applicableRules.add(rule);
                        }
                    }
                } else {
                    applicableRules.add(rule);
                }
            }
        }
    }

    private boolean checkIfChildrenAreAffected(Project parent, UUID uuid) {
        boolean isChild = false;
        if (parent.getChildren() == null || parent.getChildren().isEmpty()) {
            return false;
        }
        for (Project child : parent.getChildren()) {
            if ((child.getUuid().equals(uuid) && Boolean.TRUE.equals(child.isActive())) || isChild) {
                return true;
            }
            isChild = checkIfChildrenAreAffected(child, uuid);
        }
        return isChild;
    }
}
