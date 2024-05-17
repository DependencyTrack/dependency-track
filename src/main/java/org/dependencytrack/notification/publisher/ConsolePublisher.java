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

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.pebbletemplates.pebble.PebbleEngine;

import jakarta.json.JsonObject;
import java.io.IOException;
import java.io.PrintStream;

public class ConsolePublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(ConsolePublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().newLineTrimming(false).build();

    public void inform(final PublishContext ctx, final Notification notification, final JsonObject config) {
        final String content;
        try {
            content = prepareTemplate(notification, getTemplate(config));
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed to prepare notification content (%s)".formatted(ctx), e);
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

    @Override
    public PebbleEngine getTemplateEngine() {
        return ENGINE;
    }
}
