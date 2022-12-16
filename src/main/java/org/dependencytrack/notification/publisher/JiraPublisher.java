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
import alpine.notification.Notification;
import alpine.security.crypto.DataEncryption;
import io.pebbletemplates.pebble.PebbleEngine;
import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.persistence.QueryManager;

import javax.json.JsonObject;
import java.util.Map;

import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_USERNAME;

/**
 * Class that handles publishing a ticket to a Jira instance when a new notification is received.
 *
 * @author Mvld3r
 * @since 4.7
 */
public class JiraPublisher extends AbstractWebhookPublisher implements Publisher {
    private static final Logger LOGGER = Logger.getLogger(JiraPublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().defaultEscapingStrategy("json").build();
    private String jiraProjectKey;
    private String jiraTicketType;

    @Override
    public void inform(final Notification notification, final JsonObject config) {
        jiraTicketType = config.getString("jiraTicketType");
        jiraProjectKey = config.getString(CONFIG_DESTINATION);
        publish(DefaultNotificationPublishers.JIRA.getPublisherName(), getTemplate(config), notification, config);
    }

    @Override
    public PebbleEngine getTemplateEngine() {
        return ENGINE;
    }

    @Override
    public String getDestinationUrl(final JsonObject config) {
        try (final QueryManager qm = new QueryManager()) {
            final String baseUrl = qm.getConfigProperty(JIRA_URL.getGroupName(), JIRA_URL.getPropertyName()).getPropertyValue();
            return (baseUrl.endsWith("/") ? baseUrl : baseUrl + '/') + "rest/api/2/issue";
        } catch (final Exception e) {
            throw new PublisherException("An error occurred during the retrieval of the Jira URL", e);
        }

    }

    @Override
    public BasicAuthCredentials getBasicAuthCredentials() {
        try (final QueryManager qm = new QueryManager()) {
            final String jiraUsername = qm.getConfigProperty(JIRA_USERNAME.getGroupName(), JIRA_USERNAME.getPropertyName()).getPropertyValue();
            final String encryptedPassword = qm.getConfigProperty(JIRA_PASSWORD.getGroupName(), JIRA_PASSWORD.getPropertyName()).getPropertyValue();
            final String jiraPassword = (encryptedPassword == null) ? null : DataEncryption.decryptAsString(encryptedPassword);
            return new BasicAuthCredentials(jiraUsername, jiraPassword);
        } catch (final Exception e) {
            throw new PublisherException("An error occurred during the retrieval of Jira credentials", e);
        }
    }

    @Override
    public void enrichTemplateContext(final Map<String, Object> context) {
        context.put("jiraProjectKey", jiraProjectKey);
        context.put("jiraTicketType", jiraTicketType);
    }
}
