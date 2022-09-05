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

import alpine.security.crypto.DataEncryption;
import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.common.util.UrlUtil;
import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import javax.json.JsonObject;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_USERNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_PASSWORD;
import kong.unirest.UnirestInstance;
import org.dependencytrack.common.UnirestFactory;
import kong.unirest.HttpResponse;

public class JiraPublisher extends AbstractWebhookPublisher implements Publisher {
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().defaultEscapingStrategy("json").build();
    private static final PebbleTemplate TEMPLATE = ENGINE.getTemplate("templates/notification/publisher/jira.peb");
    private String jiraUsername;
    private String jiraPassword;
    private String jiraProjectKey;
    private String jiraTicketType;
    final Logger logger = Logger.getLogger(this.getClass());
    public void inform(final Notification notification, final JsonObject config) {
        publish(DefaultNotificationPublishers.JIRA.getPublisherName(), TEMPLATE, notification, config);
    }

    @Override
    public String prepareTemplate(final Notification notification, final PebbleTemplate template) {
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
                if (notification.getSubject() instanceof NewVulnerabilityIdentified) {
                    final NewVulnerabilityIdentified subject = (NewVulnerabilityIdentified) notification.getSubject();
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof NewVulnerableDependency) {
                    final NewVulnerableDependency subject = (NewVulnerableDependency) notification.getSubject();
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof AnalysisDecisionChange) {
                    final AnalysisDecisionChange subject = (AnalysisDecisionChange) notification.getSubject();
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                } else if (notification.getSubject() instanceof BomConsumedOrProcessed) {
                    final BomConsumedOrProcessed subject = (BomConsumedOrProcessed) notification.getSubject();
                    context.put("subject", subject);
                    context.put("subjectJson", NotificationUtil.toJson(subject));
                }
            }
            // Jira addition:
            context.put("jiraProjectKey", jiraProjectKey);
            context.put("jiraTicketType", jiraTicketType); //TEST

            try (Writer writer = new StringWriter()) {
                template.evaluate(writer, context);
                return writer.toString();
            } catch (IOException e) {
                Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
                return null;
            }
        }
    }

    @Override
    public void publish(final String publisherName, final PebbleTemplate template, final Notification notification, final JsonObject config) {
        final Logger logger = Logger.getLogger(this.getClass());
        logger.info("Preparing to publish JIRA notification");
        if (config == null) {
            logger.warn("No configuration found. Skipping notification.");
            return;
        }

        try (QueryManager qm = new QueryManager()) {
            jiraUsername = qm.getConfigProperty(JIRA_USERNAME.getGroupName(), JIRA_USERNAME.getPropertyName()).getPropertyValue();
            final String password = qm.getConfigProperty(JIRA_PASSWORD.getGroupName(), JIRA_PASSWORD.getPropertyName()).getPropertyValue();
            jiraPassword = (password != null) ? DataEncryption.decryptAsString(password) : null;
            final String configDestination = config.getString("destination");
            URL url;
            String destination;
            url = new URL(configDestination);
            destination = url.getProtocol()+"://" + url.getAuthority() + "/rest/api/2/issue";
            final String[] pathElements = url.getPath().split("/");
            if(pathElements.length == 0) {
                logger.error("No Jira Project given");
                return;
            }
            jiraProjectKey = pathElements[pathElements.length-1];
            jiraTicketType = config.getString("jira_tickettype");
            final String content = prepareTemplate(notification, template);
            if (destination == null || content == null) {
                logger.warn("A destination or template was not found. Skipping notification");
                return;
            }

            final UnirestInstance ui = UnirestFactory.getUnirestInstance();
            final HttpResponse response = ui.post(destination)
                .header("content-type", "application/json")
                .header("authorization", "Basic " + Base64.getEncoder().encodeToString( (jiraUsername+":"+jiraPassword).getBytes() ) )
                .header("accept", "application/json")
                .body(content)
                .asEmpty();

            logger.debug("jira issue creation response code: " + response.getStatus());
            if (response.isSuccess()) {
                logger.debug("jira issue creation response body: " + response.getBody().toString());
            }

        }
        catch(Exception e) {
            logger.error("jira issue creation error: ", e);
        }
    }
}
