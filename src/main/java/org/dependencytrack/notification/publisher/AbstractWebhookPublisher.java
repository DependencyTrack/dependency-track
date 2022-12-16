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
import io.pebbletemplates.pebble.template.PebbleTemplate;
import kong.unirest.Header;
import kong.unirest.Headers;
import kong.unirest.UnirestInstance;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.exception.PublisherException;

import javax.json.JsonObject;
import java.util.stream.Collectors;

public abstract class AbstractWebhookPublisher implements Publisher {

    public void publish(final String publisherName, final PebbleTemplate template, final Notification notification, final JsonObject config) {
        final Logger logger = Logger.getLogger(this.getClass());
        logger.debug("Preparing to publish " + publisherName + " notification");
        if (config == null) {
            logger.warn("No configuration found. Skipping notification.");
            return;
        }
        final String destination = getDestinationUrl(config);
        final String content = prepareTemplate(notification, template);
        if (destination == null || content == null) {
            logger.warn("A destination or template was not found. Skipping notification");
            return;
        }
        final String mimeType = getTemplateMimeType(config);
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();

        final var headers = new Headers();
        headers.add("content-type", mimeType);
        headers.add("accept", mimeType);
        final BasicAuthCredentials credentials;
        try {
            credentials = getBasicAuthCredentials();
        } catch (PublisherException e) {
            logger.warn("An error occurred during the retrieval of credentials needed for notification publication. Skipping notification", e);
            return;
        }
        if (credentials != null) {
            headers.setBasicAuth(credentials.user(), credentials.password());
        }

        final var response = ui.post(destination)
                .headers(headers.all().stream().collect(Collectors.toMap(Header::getName, Header::getValue)))
                .body(content)
                .asString();

        if (!response.isSuccess()) {
            logger.error("An error was encountered publishing notification to " + publisherName);
            logger.error("HTTP Status : " + response.getStatus() + " " + response.getStatusText());
            logger.error("Destination: " + destination);
            logger.error("Response: " + response.getBody());
            logger.debug(content);
        }
    }

    protected String getDestinationUrl(final JsonObject config) {
        return config.getString(CONFIG_DESTINATION);
    }

    protected BasicAuthCredentials getBasicAuthCredentials() {
        return null;
    }

    protected record BasicAuthCredentials(String user, String password) {
    }
}
