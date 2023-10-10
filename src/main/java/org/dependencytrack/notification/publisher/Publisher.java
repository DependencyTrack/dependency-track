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
package org.dependencytrack.notification.publisher;

import alpine.common.logging.Logger;
import alpine.common.util.UrlUtil;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.json.JsonObject;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

public interface Publisher {

    String CONFIG_TEMPLATE_KEY = "template";

    String CONFIG_TEMPLATE_MIME_TYPE_KEY = "mimeType";

    String CONFIG_DESTINATION = "destination";

    void inform(Notification notification, JsonObject config);

    PebbleEngine getTemplateEngine();

    default PebbleTemplate getTemplate(JsonObject config) {
        try {
            String literalTemplate = config.getString(CONFIG_TEMPLATE_KEY);
            return getTemplateEngine().getLiteralTemplate(literalTemplate);
        } catch (NullPointerException | ClassCastException templateException) {
            throw new PublisherException(templateException.getMessage(), templateException);
        }
    }

    default String getTemplateMimeType(JsonObject config) {
        try {
            return config.getString(CONFIG_TEMPLATE_MIME_TYPE_KEY);
        } catch (NullPointerException | ClassCastException templateException) {
            throw new PublisherException(templateException.getMessage(), templateException);
        }
    }

    default void enrichTemplateContext(final Map<String, Object> context) {
    }

    default String prepareTemplate(final Notification notification, final PebbleTemplate template) {

        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty baseUrlProperty = qm.getConfigProperty(
                    ConfigPropertyConstants.GENERAL_BASE_URL.getGroupName(),
                    ConfigPropertyConstants.GENERAL_BASE_URL.getPropertyName()
            );

            final Map<String, Object> context = new HashMap<>();
            final long epochSecond = notification.getTimestamp().toEpochSecond(
                    ZoneId.systemDefault().getRules()
                            .getOffset(notification.getTimestamp())
            );
            context.put("timestampEpochSecond", epochSecond);
            context.put("timestamp", notification.getTimestamp().toString());
            context.put("notification", notification);
            if (baseUrlProperty != null) {
                context.put("baseUrl", UrlUtil.normalize(baseUrlProperty.getPropertyValue()));
            } else {
                context.put("baseUrl", "");
            }

            if (NotificationScope.PORTFOLIO.name().equals(notification.getScope())) {
                if (notification.getSubject() instanceof final NewVulnerabilityIdentified subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final NewVulnerableDependency subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final AnalysisDecisionChange subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final ViolationAnalysisDecisionChange subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final BomConsumedOrProcessed subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final BomProcessingFailed subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final VexConsumedOrProcessed subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof final PolicyViolationIdentified subject) {
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                }
            }
            enrichTemplateContext(context);

            try (final Writer writer = new StringWriter()) {
                template.evaluate(writer, context);
                return writer.toString();
            } catch (IOException e) {
                Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
                return null;
            }
        }
    }

}
