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

import alpine.logging.Logger;
import alpine.notification.Notification;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestInstance;
import org.dependencytrack.common.UnirestFactory;
import javax.json.JsonObject;

public abstract class AbstractWebhookPublisher implements Publisher {

    public void publish(final String publisherName, final PebbleTemplate template, final Notification notification, final JsonObject config) {
        final Logger logger = Logger.getLogger(this.getClass());
        logger.debug("Preparing to publish notification");
        if (config == null) {
            logger.warn("No configuration found. Skipping notification.");
            return;
        }
        final String destination = config.getString("destination");
        final String content = prepareTemplate(notification, template);
        if (destination == null || content == null) {
            logger.warn("A destination or template was not found. Skipping notification");
            return;
        }

        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpResponse<JsonNode> response = ui.post(destination)
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .body(content)
                .asJson();

        if (response.getStatus() < 200 || response.getStatus() > 299) {
            logger.error("An error was encountered publishing notification to " + publisherName);
            logger.error("HTTP Status : " + response.getStatus() + " " + response.getStatusText());
            logger.error("Destination: " + destination);
            logger.debug(content);
        }
    }
}
