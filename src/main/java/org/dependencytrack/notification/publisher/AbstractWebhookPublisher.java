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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.util.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.JsonObject;
import java.io.IOException;

public abstract class AbstractWebhookPublisher implements Publisher {

    public void publish(final PublishContext ctx, final PebbleTemplate template, final Notification notification, final JsonObject config) {
        final Logger logger = LoggerFactory.getLogger(getClass());

        if (config == null) {
            logger.warn("No publisher configuration found; Skipping notification (%s)".formatted(ctx));
            return;
        }

        final String destination = getDestinationUrl(config);
        if (destination == null) {
            logger.warn("No destination configured; Skipping notification (%s)".formatted(ctx));
            return;
        }

        final AuthCredentials credentials;
        try {
            credentials = getAuthCredentials();
        } catch (RuntimeException e) {
            logger.warn("""
                    An error occurred during the retrieval of credentials needed for notification \
                    publication; Skipping notification (%s)""".formatted(ctx), e);
            return;
        }

        final String content;
        try {
            content = prepareTemplate(notification, template);
        } catch (IOException | RuntimeException e) {
            logger.error("Failed to prepare notification content (%s)".formatted(ctx), e);
            return;
        }

        final String mimeType = getTemplateMimeType(config);
        var request = new HttpPost(destination);
        request.addHeader("content-type", mimeType);
        request.addHeader("accept", mimeType);
        if (credentials != null) {
            if(credentials.user() != null) {
                request.addHeader("Authorization", HttpUtil.basicAuthHeaderValue(credentials.user(), credentials.password()));
            } else {
                request.addHeader("Authorization", "Bearer " + credentials.password);
            }
        } else if (getToken(config) != null) {
            request.addHeader(getTokenHeader(config), getToken(config));
        }

        try {
            request.setEntity(new StringEntity(content));
            try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                final int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode < 200 || statusCode >= 300) {
                    logger.warn("Destination responded with with status code %d, likely indicating a processing failure (%s)"
                            .formatted(statusCode, ctx));
                    if (logger.isDebugEnabled()) {
                        logger.debug("Response headers: %s".formatted((Object[]) response.getAllHeaders()));
                        logger.debug("Response body: %s".formatted(EntityUtils.toString(response.getEntity())));
                    }
                } else if (ctx.shouldLogSuccess()) {
                    logger.info("Destination acknowledged reception of notification with status code %d (%s)"
                            .formatted(statusCode, ctx));
                }
            }
        } catch (IOException ex) {
            handleRequestException(ctx, logger, ex);
        }
    }

    protected String getDestinationUrl(final JsonObject config) {
        return config.getString(CONFIG_DESTINATION, null);
    }

    protected AuthCredentials getAuthCredentials() {
        return null;
    }

    protected String getToken(final JsonObject config) {
        return config.getString(CONFIG_TOKEN, null);
    }

    protected String getTokenHeader(final JsonObject config) {
        return config.getString(CONFIG_TOKEN_HEADER, "X-Api-Key");
    }

    protected record AuthCredentials(String user, String password) {
    }

    protected void handleRequestException(final PublishContext ctx, final Logger logger, final Exception e) {
        logger.error("Failed to send notification request (%s)".formatted(ctx), e);
    }

}
