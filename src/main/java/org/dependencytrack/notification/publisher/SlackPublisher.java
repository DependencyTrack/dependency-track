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
import alpine.server.cache.AbstractCacheManager;
import alpine.server.cache.CacheManager;
import io.pebbletemplates.pebble.PebbleEngine;
import org.apache.commons.codec.digest.DigestUtils;

import javax.json.JsonObject;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SlackPublisher extends AbstractWebhookPublisher implements Publisher {

    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().defaultEscapingStrategy("json").build();
    private static final Pattern WEBHOOK_URL_PATTERN =
            Pattern.compile("^(?<prefix>https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/)(?<secret>[A-Za-z0-9]{23,25})$");

    private final AbstractCacheManager cacheManager;

    public SlackPublisher() {
        this(CacheManager.getInstance());
    }

    SlackPublisher(final AbstractCacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void inform(final PublishContext ctx, final Notification notification, final JsonObject config) {
        publish(ctx, getTemplate(config), notification, config);
    }

    @Override
    public PebbleEngine getTemplateEngine() {
        return ENGINE;
    }

    @Override
    protected String maybeSanitizeDestinationUrl(final String destinationUrl) {
        if (destinationUrl == null) {
            return null;
        }

        return cacheManager.get(String.class,
                "%s-%s".formatted(getClass().getSimpleName(), DigestUtils.sha1Hex(destinationUrl)),
                key -> {
                    final Matcher matcher = WEBHOOK_URL_PATTERN.matcher(destinationUrl);
                    if (matcher.find()) {
                        final String prefix = matcher.group("prefix");
                        final String secret = matcher.group("secret");
                        final String maskedSecret = "*".repeat(secret.length() - 4) + secret.substring(secret.length() - 4);
                        return prefix + maskedSecret;
                    }

                    return destinationUrl;
                });
    }

}
