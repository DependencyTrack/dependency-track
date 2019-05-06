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
import alpine.notification.NotificationLevel;
import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import javax.json.JsonObject;
import java.io.PrintStream;

public class ConsolePublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(ConsolePublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().newLineTrimming(false).build();
    private static final PebbleTemplate TEMPLATE = ENGINE.getTemplate("templates/notification/publisher/console.peb");

    public void inform(final Notification notification, final JsonObject config) {
        final String content = prepareTemplate(notification, TEMPLATE);
        if (content == null) {
            LOGGER.warn("A template was not found. Skipping notification");
            return;
        }
        final PrintStream ps;
        if (notification.getLevel() == NotificationLevel.ERROR) {
            ps = System.err;
        } else {
            ps = System.out;
        }
        ps.println(content);
    }
}
