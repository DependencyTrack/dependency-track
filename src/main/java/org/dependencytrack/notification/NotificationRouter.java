/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.notification;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.Subscriber;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
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

public class NotificationRouter implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NotificationRouter.class);

    public void inform(Notification notification) {
        for (NotificationRule rule: resolveRules(notification)) {

            // Not all publishers need configuration (i.e. ConsolePublisher)
            JsonObject config = null;
            if (rule.getPublisherConfig() != null) {
                try (StringReader stringReader = new StringReader(rule.getPublisherConfig());
                     final JsonReader jsonReader = Json.createReader(stringReader)) {
                    config = jsonReader.readObject();
                } catch (Exception e) {
                    LOGGER.error("An error occurred while preparing the configuration for the notification publisher", e);
                }
            }
            try {
                final Class<?> publisherClass = Class.forName(rule.getPublisher().getPublisherClass());
                if (Publisher.class.isAssignableFrom(publisherClass)) {
                    final Publisher publisher = (Publisher)publisherClass.getDeclaredConstructor().newInstance();
                    publisher.inform(notification, config);
                } else {
                    LOGGER.error("The defined notification publisher is not assignable from " + Publisher.class.getCanonicalName());
                }
            } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | InvocationTargetException | IllegalAccessException e) {
                LOGGER.error("An error occurred while instantiating a notification publisher", e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<NotificationRule> resolveRules(Notification notification) {
        // The notification rules to process for this specific notification
        final List<NotificationRule> rules = new ArrayList<>();

        if (notification.getScope() == null || notification.getGroup() == null || notification.getLevel() == null) {
            return rules;
        }
        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final Query query = pm.newQuery(NotificationRule.class);

            StringBuilder sb = new StringBuilder();

            final NotificationLevel level = notification.getLevel();
            if (NotificationLevel.INFORMATIONAL == level) {
                sb.append("(notificationLevel == 'INFORMATIONAL' || notificationLevel == 'WARNING' || notificationLevel == 'ERROR') && ");
            } else if (NotificationLevel.WARNING == level) {
                sb.append("(notificationLevel == 'WARNING' || notificationLevel == 'ERROR') && ");
            } else if (NotificationLevel.ERROR == level) {
                sb.append("notificationLevel == 'ERROR' && ");
            }

            sb.append("enabled == true && scope == :scope"); //todo: improve this - this only works for testing
            query.setFilter(sb.toString());
            List<NotificationRule> result = (List<NotificationRule>)query.execute(NotificationScope.valueOf(notification.getScope()));


            if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() != null && notification.getSubject() instanceof NewVulnerabilityIdentified) {
                final NewVulnerabilityIdentified subject = (NewVulnerabilityIdentified) notification.getSubject();
                final Set<Project> affectedProjects = subject.getAffectedProjects();
                /*
                if the rule specified one or more projects as targets, reduce the execution
                of the notification down to those projects that the rule matches and which
                also match projects affected by the vulnerability.
                 */
                for (NotificationRule rule: result) {
                    if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                        if (rule.getProjects() != null && rule.getProjects().size() > 0) {
                            for (Project project : rule.getProjects()) {
                                for (Project affectedProject : affectedProjects) {
                                    if (affectedProject.getUuid().equals(project.getUuid())) {
                                        rules.add(rule);
                                    }
                                }
                            }
                        } else {
                            rules.add(rule);
                        }
                    }
                }
            } else if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())
                    && notification.getSubject() != null && notification.getSubject() instanceof NewVulnerableDependency) {
                final NewVulnerableDependency subject = (NewVulnerableDependency) notification.getSubject();
                /*
                if the rule specified one or more projects as targets, reduce the execution
                of the notification down to those projects that the rule matches and which
                also match projects affected by the vulnerability.
                 */
                for (NotificationRule rule: result) {
                    if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                        if (rule.getProjects() != null && rule.getProjects().size() > 0) {
                            for (Project project : rule.getProjects()) {
                                if (project.getUuid().equals(subject.getDependency().getProject().getUuid())) {
                                    rules.add(rule);
                                }
                            }
                        } else {
                            rules.add(rule);
                        }
                    }
                }
            } else {
                for (NotificationRule rule: result) {
                    if (rule.getNotifyOn().contains(NotificationGroup.valueOf(notification.getGroup()))) {
                        rules.add(rule);
                    }
                }
            }
        }
        return rules;
    }

}
