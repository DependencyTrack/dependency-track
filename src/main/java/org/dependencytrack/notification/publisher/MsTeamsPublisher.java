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
import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import org.dependencytrack.util.HttpClientFactory;
import javax.json.JsonObject;

public class MsTeamsPublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(MsTeamsPublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().build();
    private static final PebbleTemplate TEMPLATE = ENGINE.getTemplate("templates/notification/publisher/msteams.peb");

    public void inform(Notification notification, JsonObject config) {
        if (config == null) {
            LOGGER.debug("No configuration found. Skipping notification.");
            return;
        }
        final String destination = config.getString("destination");
        final String content = prepareTemplate(notification, TEMPLATE);
        if (destination == null || content == null) {
            LOGGER.debug("A destination or template was not found. Skipping notification");
            return;
        }

        Unirest.setHttpClient(HttpClientFactory.createClient());
        final HttpResponse<JsonNode> response = Unirest.post(destination)
                .header("accept", "application/json")
                .body(content)
                .asJson();

        if (response.getStatus() != 200) {
            LOGGER.error("An error was encountered publishing notification to Microsoft Teams: " + response.getStatusText());
        }
    }

}
