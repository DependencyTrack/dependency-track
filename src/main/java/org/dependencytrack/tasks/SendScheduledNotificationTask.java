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
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Rule;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.publisher.PublishContext;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
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
            for (NotificationGroup group : rule.getNotifyOn()) {
                final Notification notificationProxy = new Notification()
                        .scope(rule.getScope())
                        .group(group)
                        .title(rule.getName())
                        .level(rule.getNotificationLevel())
                        .content("") // TODO: evaluate use and creation of content here
                        .subject(null); // TODO: generate helper class here

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
                    } else {
                        LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName() + " (%s)".formatted(ruleCtx));
                    }
                } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException
                        | InvocationTargetException | IllegalAccessException e) {
                    LOGGER.error(
                            "An error occurred while instantiating a notification publisher (%s)".formatted(ruleCtx),
                            e);
                } catch (PublisherException publisherException) {
                    LOGGER.error("An error occurred during the publication of the notification (%s)".formatted(ruleCtx),
                            publisherException);
                }
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
}
