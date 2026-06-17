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
package org.dependencytrack.notification.api.publishing;

import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.Set;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Context of a notification publishing operation.
 *
 * @since 5.0.0
 */
public final class NotificationPublishContext {

    private final @Nullable RuntimeConfig ruleConfig;
    private final Supplier<Set<NotificationRuleContact>> ruleContactsSupplier;
    private final NotificationTemplateRenderer templateRenderer;
    private @Nullable Set<NotificationRuleContact> ruleContacts;

    public NotificationPublishContext(
            @Nullable RuntimeConfig ruleConfig,
            Supplier<Set<NotificationRuleContact>> ruleContactsSupplier,
            NotificationTemplateRenderer templateRenderer) {
        this.ruleConfig = ruleConfig;
        this.ruleContactsSupplier = requireNonNull(ruleContactsSupplier, "ruleContactsSupplier must not be null");
        this.templateRenderer = requireNonNull(templateRenderer, "templateRenderer must not be null");
    }

    public NotificationPublishContext(
            @Nullable RuntimeConfig ruleConfig,
            NotificationTemplateRenderer templateRenderer) {
        this(ruleConfig, Collections::emptySet, templateRenderer);
    }

    public @Nullable RuntimeConfig ruleConfig() {
        return ruleConfig;
    }

    public <C extends RuntimeConfig> C ruleConfig(Class<C> clazz) {
        if (ruleConfig == null) {
            throw new IllegalStateException("Missing rule configuration");
        }

        return clazz.cast(ruleConfig);
    }

    public Set<NotificationRuleContact> ruleContacts() {
        if (ruleContacts == null) {
            ruleContacts = ruleContactsSupplier.get();
        }

        return ruleContacts;
    }

    public NotificationTemplateRenderer templateRenderer() {
        return templateRenderer;
    }

}
