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
package org.owasp.dependencytrack.notification.publisher;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import org.owasp.dependencytrack.notification.NotificationConstants;
import org.owasp.dependencytrack.util.HttpClientFactory;
import javax.json.JsonObject;
import java.time.ZoneId;

public class SlackPublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(SlackPublisher.class);

    public void inform(Notification notification, JsonObject config) {
        final long timestamp = notification.getTimestamp().toEpochSecond(
                ZoneId.systemDefault().getRules()
                .getOffset(notification.getTimestamp())
        );
        final String destination = config.getString("destination");
        final String body;


        /*
         * Construct message body for system notifications.
         */
        if (NotificationConstants.Scope.SYSTEM.name().equals(notification.getScope())) {
            String color = "#c0c0c0";
            if (notification.getLevel() == NotificationLevel.INFORMATIONAL) {
                color = "good";
            } else if (notification.getLevel() == NotificationLevel.WARNING) {
                color = "warning";
            } else if (notification.getLevel() == NotificationLevel.ERROR) {
                color = "danger";
            }
            body = "{\n" +
                    "  \"icon_url\": \"https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-icon-centered-blue-background-500px.png\",\n" +
                    "  \"username\": \"Dependency-Track\",\n" +
                    "  \"attachments\": [\n" +
                    "    {\n" +
                    "      \"fields\": [\n" +
                    "        {\n" +
                    "          \"title\": \"Level\",\n" +
                    "          \"value\": \"" + notification.getLevel() + "\",\n" +
                    "        },\n" +
                    "        {\n" +
                    "          \"title\": \"Scope\",\n" +
                    "          \"value\": \"" + notification.getScope() + "\",\n" +
                    "        },\n" +
                    "        {\n" +
                    "          \"title\": \"Group\",\n" +
                    "          \"value\": \"" + notification.getGroup() + "\",\n" +
                    "        }\n" +
                    "      ],\n" +
                    "      \"color\": \"" + color + "\",\n" +
                    "      \"ts\": \"" + timestamp + "\",\n" +
                    "      \"title\": \"" + notification.getTitle() + "\",\n" +
                    "      \"text\": \"" + notification.getContent() + "\"\n" +
                    "    }\n" +
                    "  ]\n" +
                    "}";
        } else {
        /*
         * Construct message body for portfolio notifications.
         */
            body = ""; //todo
        }

        Unirest.setHttpClient(HttpClientFactory.createClient());
        final HttpResponse<JsonNode> response = Unirest.post(destination)
                .header("accept", "application/json")
                .body(body)
                .asJson();

        if (response.getStatus() != 200) {
            LOGGER.error("An error was encountered publishing notification to Slack: " + response.getStatusText());
        }
    }

}
