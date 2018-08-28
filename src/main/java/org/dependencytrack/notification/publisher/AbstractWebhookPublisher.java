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

import alpine.logging.Logger;
import alpine.notification.Notification;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import org.dependencytrack.util.HttpClientFactory;
import javax.json.JsonObject;

public abstract class AbstractWebhookPublisher implements Publisher {

    public void publish(String publisherName, PebbleTemplate template, Notification notification, JsonObject config) {
        final Logger logger = Logger.getLogger(this.getClass());
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

        Unirest.setHttpClient(HttpClientFactory.createClient());
        final HttpResponse<JsonNode> response = Unirest.post(destination)
                .header("accept", "application/json")
                .body(content)
                .asJson();

        if (response.getStatus() < 200 || response.getStatus() > 299) {
            logger.error("An error was encountered publishing notification to " + publisherName + ": " + response.getStatusText());
            logger.debug(content);
        }
    }
}
