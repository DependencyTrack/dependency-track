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
package org.owasp.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import org.apache.log4j.Logger;
import org.owasp.dependencytrack.notification.NotificationConstants;
import org.owasp.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractPublisher {

    protected String prepareTemplate(Notification notification, PebbleTemplate template) {
        final Map<String, Object> context = new HashMap<>();
        final long epochSecond = notification.getTimestamp().toEpochSecond(
                ZoneId.systemDefault().getRules()
                        .getOffset(notification.getTimestamp())
        );
        context.put("timestampEpochSecond", epochSecond);
        context.put("timestamp", notification.getTimestamp().toString());
        context.put("notification", notification);
        if (NotificationConstants.Scope.SYSTEM.name().equals(notification.getScope())) {
            context.put("content", notification.getContent());
            context.put("title", notification.getTitle());
        } else if (NotificationConstants.Scope.PORTFOLIO.name().equals(notification.getScope())) {
            final NewVulnerabilityIdentified newVuln = (NewVulnerabilityIdentified) notification.getSubject();
            final String vulnId = newVuln.getVulnerability().getVulnId();
            String content = (newVuln.getVulnerability().getTitle() != null) ? vulnId + ": " + newVuln.getVulnerability().getTitle() : vulnId;
            if (newVuln.getVulnerability().getDescription() != null) {
                content = newVuln.getVulnerability().getDescription();
            }
            context.put("title", newVuln.getComponent().getName());
            context.put("severity", newVuln.getVulnerability().getSeverity().name());
            context.put("source", newVuln.getVulnerability().getSource());
            context.put("vulnId", vulnId);
            context.put("content", content);
        }

        final String body;
        try (Writer writer = new StringWriter()) {
            template.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
            return null;
        }
    }
}
