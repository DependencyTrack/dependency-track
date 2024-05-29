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

import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Rule;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.publisher.PublishContext;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.ScheduledNewVulnerabilitiesIdentified;
import org.dependencytrack.notification.vo.ScheduledPolicyViolationsIdentified;
import org.dependencytrack.persistence.QueryManager;

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_KEY;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY;

public class SendScheduledNotificationTask implements Runnable {
    private UUID scheduledNotificationRuleUuid;
    private static final Logger LOGGER = Logger.getLogger(SendScheduledNotificationTask.class);

    public SendScheduledNotificationTask(UUID scheduledNotificationRuleUuid) {
        this.scheduledNotificationRuleUuid = scheduledNotificationRuleUuid;
    }

    @Override
    public void run() {
        try (var qm = new QueryManager()) {
            var rule = qm.getObjectByUuid(ScheduledNotificationRule.class, scheduledNotificationRuleUuid);
            final List<Long> projectIds = rule.getProjects().stream().map(proj -> proj.getId()).toList();
            Boolean errorsDuringExecution = false;
            Boolean atLeastOneSuccessfulPublish = false;
            
            for (NotificationGroup group : rule.getNotifyOn()) {
                final Notification notificationProxy = new Notification()
                        .scope(rule.getScope())
                        .group(group)
                        .title(generateNotificationTitle(rule, group))
                        .level(rule.getNotificationLevel());

                switch (group) {
                    case NEW_VULNERABILITY:
                        var newProjectVulnerabilities = qm.getNewVulnerabilitiesForProjectsSince(rule.getLastExecutionTime(), projectIds);
                        if(newProjectVulnerabilities.isEmpty() && rule.getPublishOnlyWithUpdates())
                            continue;
                        ScheduledNewVulnerabilitiesIdentified vulnSubject = new ScheduledNewVulnerabilitiesIdentified(newProjectVulnerabilities);
                        notificationProxy
                                .content(generateVulnerabilityNotificationContent(rule,
                                                                     vulnSubject.getNewVulnerabilitiesTotal(),
                                                                     newProjectVulnerabilities.keySet().stream().toList(),
                                                                     rule.getLastExecutionTime()))
                                .subject(vulnSubject);
                        break;
                    case POLICY_VIOLATION:
                        var newProjectPolicyViolations = qm.getNewPolicyViolationsForProjectsSince(rule.getLastExecutionTime(), projectIds);
                        if(newProjectPolicyViolations.isEmpty() && rule.getPublishOnlyWithUpdates())
                            continue;
                        ScheduledPolicyViolationsIdentified policySubject = new ScheduledPolicyViolationsIdentified(newProjectPolicyViolations);
                        notificationProxy
                            .content(generatePolicyNotificationContent(rule,
                                                                 policySubject.getNewPolicyViolationsTotal(),
                                                                 newProjectPolicyViolations.keySet().stream().toList(),
                                                                 rule.getLastExecutionTime()))
                            .subject(policySubject);
                        break;
                    default:
                        LOGGER.error(group.name() + " is not a supported notification group for scheduled publishing");
                        errorsDuringExecution |= true;
                        continue;
                }

                final PublishContext ctx = PublishContext.from(notificationProxy);
                final PublishContext ruleCtx =ctx.withRule(rule);

                // Not all publishers need configuration (i.e. ConsolePublisher)
                JsonObject config = Json.createObjectBuilder().build();
                if (rule.getPublisherConfig() != null) {
                    try (StringReader stringReader = new StringReader(rule.getPublisherConfig());
                         final JsonReader jsonReader = Json.createReader(stringReader)) {
                        config = jsonReader.readObject();
                    } catch (Exception e) {
                        LOGGER.error("An error occurred while preparing the configuration for the notification publisher (%s)".formatted(ruleCtx), e);
                        errorsDuringExecution |= true;
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
                        if (publisherClass != SendMailPublisher.class || rule.getTeams().isEmpty() || rule.getTeams() == null) {
                            publisher.inform(ruleCtx, restrictNotificationToRuleProjects(notificationProxy, rule), notificationPublisherConfig);
                        } else {
                            ((SendMailPublisher) publisher).inform(ruleCtx, restrictNotificationToRuleProjects(notificationProxy, rule), notificationPublisherConfig, rule.getTeams());
                        }
                        atLeastOneSuccessfulPublish |= true;
                    } else {
                        LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName() + " (%s)".formatted(ruleCtx));
                    }
                } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException
                        | InvocationTargetException | IllegalAccessException e) {
                    LOGGER.error("An error occurred while instantiating a notification publisher (%s)".formatted(ruleCtx), e);
                    errorsDuringExecution |= true;
                } catch (PublisherException publisherException) {
                    LOGGER.error("An error occurred during the publication of the notification (%s)".formatted(ruleCtx), publisherException);
                    errorsDuringExecution |= true;
                }
            }
            if (!errorsDuringExecution || atLeastOneSuccessfulPublish) {
                /*
                 * Update last execution time after successful operation (even without
                 * publishing) to avoid duplicate notifications in the next run and signalize
                 * user indirectly, that operation has ended without failure
                 */
                qm.updateScheduledNotificationRuleLastExecutionTimeToNowUtc(rule);
            }
        }
    }

    private Notification restrictNotificationToRuleProjects(final Notification initialNotification, final Rule rule) {
        Notification restrictedNotification = initialNotification;
        if (canRestrictNotificationToRuleProjects(initialNotification, rule)) {
            Set<String> ruleProjectsUuids = rule.getProjects().stream().map(Project::getUuid).map(UUID::toString).collect(Collectors.toSet());
            restrictedNotification = new Notification();
            restrictedNotification.setGroup(initialNotification.getGroup());
            restrictedNotification.setLevel(initialNotification.getLevel());
            restrictedNotification.scope(initialNotification.getScope());
            restrictedNotification.setContent(initialNotification.getContent());
            restrictedNotification.setTitle(initialNotification.getTitle());
            restrictedNotification.setTimestamp(initialNotification.getTimestamp());
            if (initialNotification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
                Set<Project> restrictedProjects = subject.getAffectedProjects().stream().filter(project -> ruleProjectsUuids.contains(project.getUuid().toString())).collect(Collectors.toSet());
                NewVulnerabilityIdentified restrictedSubject = new NewVulnerabilityIdentified(subject.getVulnerability(), subject.getComponent(), restrictedProjects, null);
                restrictedNotification.setSubject(restrictedSubject);
            }
        }
        return restrictedNotification;
    }

    private boolean canRestrictNotificationToRuleProjects(final Notification initialNotification, final Rule rule) {
        return initialNotification.getSubject() instanceof NewVulnerabilityIdentified
                && rule.getProjects() != null
                && !rule.getProjects().isEmpty();
    }

    private String generateNotificationTitle(final Rule rule, final NotificationGroup group) {
        return "Scheduled Notification: " + group.name();
    }

    private String generateVulnerabilityNotificationContent(final Rule rule, final List<Vulnerability> vulnerabilities, final List<Project> projects, final ZonedDateTime lastExecutionTime) {
        final String content;

        if (vulnerabilities.isEmpty()) {
            content = "No new vulnerabilities found.";
        } else {
            content = "In total, " + vulnerabilities.size() + " new vulnerabilities in " + projects.size() + " projects were found since " + lastExecutionTime.toLocalDateTime().truncatedTo(ChronoUnit.SECONDS) + ".";
        }

        return content;
    }

    private String generatePolicyNotificationContent(final Rule rule, final List<PolicyViolation> policyViolations, final List<Project> projects, final ZonedDateTime lastExecutionTime) {
        final String content;

        if (policyViolations.isEmpty()) {
            content = "No new policy violations found.";
        } else {
            content = "In total, " + policyViolations.size() + " new policy violations in " + projects.size() + " projects were found since " + lastExecutionTime.toLocalDateTime().truncatedTo(ChronoUnit.SECONDS) + ".";
        }

        return content;
    }
}
