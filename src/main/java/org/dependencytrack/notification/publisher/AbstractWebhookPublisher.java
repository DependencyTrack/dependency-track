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

import alpine.notification.Notification;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.exception.PublisherException;
import org.dependencytrack.util.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.json.JsonObject;
import java.io.IOException;

public abstract class AbstractWebhookPublisher implements Publisher {
    public void publish(final String publisherName, final PebbleTemplate template, final Notification notification, final JsonObject config) {
        final Logger logger = LoggerFactory.getLogger(getClass());
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
        var request = new HttpPost(destination);
        request.addHeader("content-type", mimeType);
        request.addHeader("accept", mimeType);
        final BasicAuthCredentials credentials;
        try {
            credentials = getBasicAuthCredentials();
        } catch (PublisherException e) {
            logger.warn("An error occurred during the retrieval of credentials needed for notification publication. Skipping notification", e);
            return;
        }
        if (credentials != null) {
            request.addHeader("Authorization", HttpUtil.basicAuthHeaderValue(credentials.user(), credentials.password()));
        }

        try {
            request.setEntity(new StringEntity(content));
            try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() < 200 || response.getStatusLine().getStatusCode() >= 300) {
                    logger.error("An error was encountered publishing notification to " + publisherName +
                            "with HTTP Status : " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase() +
                            " Destination: " + destination + " Response: " + EntityUtils.toString(response.getEntity()));
                    logger.debug(content);
                }
            }
        } catch (IOException ex) {
            handleRequestException(logger, ex);
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

    protected void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
    }
}
