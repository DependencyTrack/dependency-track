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
package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import org.apache.log4j.Logger;
import org.dependencytrack.model.Component;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import javax.json.JsonObject;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public interface Publisher {

    void inform(Notification notification, JsonObject config);

    default String prepareTemplate(final Notification notification, final PebbleTemplate template) {
        final Map<String, Object> context = new HashMap<>();
        final long epochSecond = notification.getTimestamp().toEpochSecond(
                ZoneId.systemDefault().getRules()
                        .getOffset(notification.getTimestamp())
        );
        context.put("timestampEpochSecond", epochSecond);
        context.put("timestamp", notification.getTimestamp().toString());
        context.put("title", notification.getTitle());
        context.put("notification", notification);
        if (NotificationConstants.Scope.SYSTEM.name().equals(notification.getScope())) {
            context.put("content", notification.getContent());
        } else if (NotificationConstants.Scope.PORTFOLIO.name().equals(notification.getScope())) {
            final NewVulnerabilityIdentified newVuln = (NewVulnerabilityIdentified) notification.getSubject();
            final String vulnId = newVuln.getVulnerability().getVulnId();
            String content = (newVuln.getVulnerability().getTitle() != null) ? vulnId + ": " + newVuln.getVulnerability().getTitle() : vulnId;
            if (newVuln.getVulnerability().getDescription() != null) {
                content = newVuln.getVulnerability().getDescription();
            }
            context.put("severity", newVuln.getVulnerability().getSeverity().name());
            context.put("source", newVuln.getVulnerability().getSource());
            context.put("vulnId", vulnId);
            context.put("content", content);
            context.put("affectedProjects", new ArrayList<>(newVuln.getAffectedProjects()));

            final Component component = newVuln.getComponent();
            if (component.getPurl() != null) {
                context.put("component", component.getPurl().canonicalize());
            } else {
                StringBuilder sb = new StringBuilder();
                if (component.getGroup() != null) {
                    sb.append(component.getGroup()).append(" / ");
                }
                sb.append(component.getName());
                if (component.getVersion() != null) {
                    sb.append(" ").append(component.getVersion());
                }
                context.put("component", sb.toString());
            }
        }

        try (Writer writer = new StringWriter()) {
            template.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
            return null;
        }
    }

}
