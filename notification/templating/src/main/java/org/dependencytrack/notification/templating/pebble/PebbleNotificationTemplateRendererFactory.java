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
package org.dependencytrack.notification.templating.pebble;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.cache.template.CaffeineTemplateCache;
import io.pebbletemplates.pebble.extension.core.DisallowExtensionCustomizerBuilder;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;

/**
 * Factory for {@link PebbleNotificationTemplateRenderer}s.
 * <p>
 * The factory is intended to be long-lived, and only instantiated once.
 * It maintains an instance of the Pebble template engine, the reuse of
 * which ensures efficient caching of compiled templates.
 *
 * @since 5.0.0
 */
public final class PebbleNotificationTemplateRendererFactory {

    /**
     * Name of the template context variable holding the application base URL,
     * used to construct frontend links in notification templates.
     */
    public static final String BASE_URL = "baseUrl";

    private final PebbleEngine pebbleEngine;
    private final Map<String, Supplier<Object>> contextVariableSuppliers;

    public PebbleNotificationTemplateRendererFactory(Map<String, Supplier<Object>> contextVariableSuppliers) {
        this.pebbleEngine = new PebbleEngine.Builder()
                .registerExtensionCustomizer(
                        new DisallowExtensionCustomizerBuilder()
                                .disallowedTokenParserTags(List.of("include"))
                                .build())
                .extension(new PebbleExtension())
                .defaultEscapingStrategy("json")
                .newLineTrimming(false)
                .templateCache(new CaffeineTemplateCache())
                .build();
        this.contextVariableSuppliers = unmodifiableMap(requireNonNull(
                contextVariableSuppliers, "contextVariableSuppliers must not be null"));
    }

    public NotificationTemplateRenderer createRenderer(@Nullable NotificationTemplate template) {
        return new PebbleNotificationTemplateRenderer(pebbleEngine, template, contextVariableSuppliers);
    }

}
