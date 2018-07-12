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
package org.owasp.dependencytrack.notification;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.Subscriber;
import org.owasp.dependencytrack.model.NotificationRule;
import org.owasp.dependencytrack.notification.publisher.Publisher;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

public class NotificationRouter implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NotificationRouter.class);

    public void inform(Notification notification) {
        for (NotificationRule rule: resolveRules(notification)) {

            // Not all publishers need configuration (i.e. ConsolePublisher)
            JsonObject config = null;
            if (rule.getPublisherConfig() != null) {
                try (StringReader stringReader = new StringReader(rule.getPublisherConfig());
                     JsonReader jsonReader = Json.createReader(stringReader)) {
                    config = jsonReader.readObject();
                } catch (Exception e) {
                    LOGGER.error("An error occurred while preparing the configuration for the notification publisher", e);
                }
            }
            try {
                Class publisherClass = Class.forName(rule.getNotificationPublisher().getPublisherClass());
                Publisher publisher = (Publisher) publisherClass.newInstance();
                publisher.inform(notification, config);
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                LOGGER.error("An error occurred while instantiating a notification publisher", e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<NotificationRule> resolveRules(Notification notification) {
        List<NotificationRule> rules = new ArrayList<>();
        if (notification.getScope() == null || notification.getGroup() == null || notification.getLevel() == null) {
            return rules;
        }
        try (QueryManager qm = new QueryManager()) {
            PersistenceManager pm = qm.getPersistenceManager();
            final Query query = pm.newQuery(NotificationRule.class);

            StringBuilder sb = new StringBuilder();
            sb.append("enabled == true && scope == :scope"); //todo: improve this - this only works for testing
            query.setFilter(sb.toString());

            return (List<NotificationRule>) query.execute(notification.getScope());
        }
    }

}
