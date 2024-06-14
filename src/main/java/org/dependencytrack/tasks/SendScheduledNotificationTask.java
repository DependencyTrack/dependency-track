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
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.util.stream.Collectors;

import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.publisher.PublishContext;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.notification.vo.ScheduledNewVulnerabilitiesIdentified;
import org.dependencytrack.notification.vo.ScheduledPolicyViolationsIdentified;
import org.dependencytrack.persistence.QueryManager;

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_KEY;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY;

/* 
 * The scheduled notification task is responsible for processing scheduled notifications and publishing them with the configured publisher.
 * This task must be executed by the scheduler at the defined cron interval of the referenced scheduled notification rule.
 */
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
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL); // not persistent, set manually to avoid null reference exception in PublishContext
            Boolean errorsDuringExecution = false;
            Boolean atLeastOneSuccessfulPublish = false;

            LOGGER.info("Processing notification publishing for scheduled notification rule " + rule.getUuid());
            final ZonedDateTime lastExecutionTime = ZonedDateTime.of(2024, 05, 16, 0, 0, 0, 0, ZoneOffset.UTC); // rule.getLastExecutionTime();
            
            for (NotificationGroup group : rule.getNotifyOn()) {
                List<Project> affectedProjects = List.of();
                affectedProjects = evaluateAffectedProjects(qm, rule);

                final Notification notificationProxy = new Notification()
                        .scope(rule.getScope())
                        .group(group)
                        .level(NotificationLevel.INFORMATIONAL);

                switch (group) {
                    case NEW_VULNERABILITY:
                        ScheduledNewVulnerabilitiesIdentified vulnSubject = new ScheduledNewVulnerabilitiesIdentified(affectedProjects, lastExecutionTime);
                        if(vulnSubject.getOverview().getNewVulnerabilitiesCount() == 0 && rule.getPublishOnlyWithUpdates())
                            continue;
                        notificationProxy
                                .title(vulnSubject.getOverview().getNewVulnerabilitiesCount() + " new Vulnerabilitie(s) in " + vulnSubject.getOverview().getAffectedComponentsCount() + " component(s) in Scheduled Rule '" + rule.getName() + "'")
                                .content("Find below a summary of new vulnerabilities since "
                                        + lastExecutionTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                                        + " in Scheduled Notification Rule '" + rule.getName() + "'.")
                                .subject(vulnSubject);
                        break;
                    case POLICY_VIOLATION:
                    ScheduledPolicyViolationsIdentified policySubject = new ScheduledPolicyViolationsIdentified(affectedProjects, lastExecutionTime);
                    if(policySubject.getOverview().getNewViolationsCount() == 0 && rule.getPublishOnlyWithUpdates())
                        continue;
                    notificationProxy
                            .title(policySubject.getOverview().getNewViolationsCount() + " new Policy Violation(s) in " + policySubject.getOverview().getAffectedComponentsCount() + " component(s) in Scheduled Rule '" + rule.getName() + "'")
                            .content("Find below a summary of new policy violations since "
                                    + lastExecutionTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                                    + " in Scheduled Notification Rule '" + rule.getName() + "'.")
                            .subject(policySubject);
                        break;
                    default:
                        LOGGER.warn(group.name() + " is not a supported notification group for scheduled publishing");
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
                            publisher.inform(ruleCtx, notificationProxy, notificationPublisherConfig);
                        } else {
                            ((SendMailPublisher) publisher).inform(ruleCtx, notificationProxy, notificationPublisherConfig, rule.getTeams());
                        }
                        atLeastOneSuccessfulPublish |= true;
                    } else {
                        LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName() + " (%s)".formatted(ruleCtx));
                        errorsDuringExecution |= true;
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
                LOGGER.info("Successfuly processed notification publishing for scheduled notification rule " + scheduledNotificationRuleUuid);
            }
            else {
                LOGGER.error("Errors occured while processing notification publishing for scheduled notification rule " + scheduledNotificationRuleUuid);
            }
        }
        catch (Exception e) {
            LOGGER.error("An error occurred while processing scheduled notification rule " + scheduledNotificationRuleUuid, e);
        }
    }

    private List<Project> evaluateAffectedProjects(QueryManager qm, ScheduledNotificationRule rule) {
        List<Project> affectedProjects;
        /* 
         * TODO:
         * To workaround the inconsitent parent-child relationship in projects delivered
         * by QueryManager.getAllProjects() (and some other multi-project methods), we
         * need to retrieve them one by one by their UUIDs. This way it was empirically
         * proven that the parent-child relationship is (more) consistent.
         */
        if(rule.getProjects().isEmpty()){
            // if rule does not limit to specific projects, get all projects and their children, if configured
            affectedProjects = qm.detach(qm.getAllProjects())
                    .stream()
                    .filter(p -> rule.isNotifyChildren() ? true : p.getParent() == null)
                    .collect(Collectors.toList());
        } else {
            // use projects defined in rule and with children if rule is set to notify children
            affectedProjects = qm.detach(rule.getProjects())
                    .stream()
                    .collect(Collectors.toList());
            if (rule.isNotifyChildren()) {
                extendProjectListWithChildren(affectedProjects);
            }
        }
        return affectedProjects;
    }

    private void extendProjectListWithChildren(final List<Project> affectedProjects) {
        var allProjects = List.copyOf(affectedProjects);
        try (var qm = new QueryManager()) {
            for (Project project : allProjects) {
                if (project == null || project.getChildren() == null || project.getChildren().isEmpty()) {
                    continue;
                }
                var parentIndex = affectedProjects.indexOf(project);
                var childCounter = 0;
                for (Project child : project.getChildren()) {
                    if (affectedProjects
                            .stream()
                            .filter(p -> p.getUuid().equals(child.getUuid()))
                            .findAny()
                            .isPresent()) {
                        continue;
                    }
                    childCounter++;
                    affectedProjects.add(parentIndex + childCounter, child);
                }
            }
        }
    }
}
