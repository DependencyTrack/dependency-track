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

import alpine.crypto.DataEncryption;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.util.BooleanUtil;
import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestInstance;
import kong.unirest.json.JSONObject;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.persistence.QueryManager;

import javax.json.JsonObject;
import static org.dependencytrack.model.ConfigPropertyConstants.*;

public class JiraPublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(JiraPublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().newLineTrimming(false).build();
    private static final PebbleTemplate TEMPLATE = ENGINE.getTemplate("templates/notification/publisher/jira.peb");

    public void inform(final Notification notification, final JsonObject config) {
        if (config == null) {
            LOGGER.warn("No configuration found. Skipping notification.");
            return;
        }

        String projectKey = null;
        String issueType = null;

        final String[] destinations = parseDestination(config);
        if ((destinations != null) && (destinations.length == 2)) {
            projectKey = destinations[0];
            issueType = destinations[1];
            LOGGER.debug("Parsed project key'" + projectKey + "' and issue type '" + issueType + "' from alert destination field.");
        } else {
            LOGGER.info("The destination for the Jira alert did not contain a string in the form 'project_key, issue_type_name', trying to fall back to default configuration.");
        }

        final String ticketContent = prepareTemplate(notification, TEMPLATE);
        if ((ticketContent == null) || (ticketContent.length() == 0)) {
            LOGGER.warn("The template did not create any content. Skipping notification.");
            return;
        } else {
            LOGGER.debug("Transformed template into: '" + ticketContent + "'");
        }

        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty jiraEnabled = qm.getConfigProperty(JIRA_ENABLED.getGroupName(), JIRA_ENABLED.getPropertyName());
            final ConfigProperty jiraUrl = qm.getConfigProperty(JIRA_URL.getGroupName(), JIRA_URL.getPropertyName());
            final ConfigProperty jiraUser = qm.getConfigProperty(JIRA_USERNAME.getGroupName(), JIRA_USERNAME.getPropertyName());
            final ConfigProperty jiraPass = qm.getConfigProperty(JIRA_PASSWORD.getGroupName(), JIRA_PASSWORD.getPropertyName());
            final ConfigProperty jiraProject = qm.getConfigProperty(JIRA_PROJECT.getGroupName(), JIRA_PROJECT.getPropertyName());
            final ConfigProperty jiraIssuetype = qm.getConfigProperty(JIRA_ISSUETYPE.getGroupName(), JIRA_ISSUETYPE.getPropertyName());

            if (!BooleanUtil.valueOf(jiraEnabled.getPropertyValue())) {
                LOGGER.error("Jira is disabled in configuration");
                return; // jira is not enabled
            }

            final String url = jiraUrl.getPropertyValue();
            final String username = (jiraUser.getPropertyValue() != null) ? jiraUser.getPropertyValue() : null;
            final String password = (jiraPass.getPropertyValue() != null) ? DataEncryption.decryptAsString(jiraPass.getPropertyValue()) : null;

            if (username == null) {
                LOGGER.error("Jira configuration is missing username");
                return;
            }
            if (password == null) {
                LOGGER.error("Jira configuration is missing password");
                return;
            }
            if (projectKey == null) {
                projectKey = jiraProject.getPropertyValue();
            }
            if (issueType == null) {
                issueType = jiraIssuetype.getPropertyValue();
            }
            if ((projectKey == null) || (issueType == null)) {
                LOGGER.error("Could not determine project key or issue type. Skipping notification.");
                return;
            }

            JSONObject content     = new JSONObject();
            JSONObject fields      = new JSONObject(ticketContent);
            JSONObject project     = new JSONObject().put("key", projectKey);
            JSONObject issuetype   = new JSONObject().put("name", issueType);

            fields.put("project", project);
            fields.put("issuetype", issuetype);
            content.put("fields", fields);

            LOGGER.debug("Created Jira notification: '" + content + "'");

            final UnirestInstance ui = UnirestFactory.getUnirestInstance();
            LOGGER.info("Sending Jira Ticket to instance at URL '" + url + "'");
            final HttpResponse<JsonNode> response = ui.post(url + "/rest/api/2/issue/")
                .basicAuth(username, password)
                .contentType("application/json")
                .accept("application/json")
                .body(content.toString())
                .asJson();
            if (response.isSuccess()) {
                LOGGER.info("Created Jira ticket: " + response.getBody().toString());
            } else {
                LOGGER.error("Failed to create Jira ticket with response " + response.getStatus() + ": " + response.getBody());
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred sending output jira notification", e);
        }
    }

    static String[] parseDestination(final JsonObject config) {
        String destinationString = config.getString("destination");
        if ((destinationString == null) || destinationString.isEmpty()) {
            return null;
        }
        return destinationString.split(",");
    }
}
