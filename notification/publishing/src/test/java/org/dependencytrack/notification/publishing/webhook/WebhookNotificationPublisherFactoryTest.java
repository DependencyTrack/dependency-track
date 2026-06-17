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
package org.dependencytrack.notification.publishing.webhook;

import org.dependencytrack.notification.publishing.AbstractNotificationPublisherFactoryTest;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class WebhookNotificationPublisherFactoryTest extends AbstractNotificationPublisherFactoryTest<WebhookNotificationPublisherFactory> {

    protected WebhookNotificationPublisherFactoryTest() {
        super(WebhookNotificationPublisherFactory.class);
    }

    @Test
    void defaultTemplateShouldNotReturnNull() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            assertThat(publisherFactory.defaultTemplate()).isNotNull();
        }
    }

    @Test
    void shouldRejectConfigWithAuthHeaderValueButNoAuthHeaderName() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();
            config.setAuthHeaderValue("some-secret");

            assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config))
                    .withMessageContaining("authHeaderName is required when authHeaderValue is set");
        }
    }

    @Test
    void shouldRejectConfigWithAuthHeaderNameButNoAuthHeaderValue() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();
            config.setAuthHeaderName("Authorization");

            assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config))
                    .withMessageContaining("authHeaderValue is required when authHeaderName is set");
        }
    }

    @Test
    void shouldRejectConfigWithBlankAuthHeaderName() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();
            config.setAuthHeaderName("  ");
            config.setAuthHeaderValue("Bearer token");

            assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config))
                    .withMessageContaining("authHeaderName must not be blank");
        }
    }

    @Test
    void shouldRejectConfigWithBlankAuthHeaderValue() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();
            config.setAuthHeaderName("Authorization");
            config.setAuthHeaderValue("  ");

            assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config))
                    .withMessageContaining("authHeaderValue must not be blank");
        }
    }

    @Test
    void shouldAcceptConfigWithAuthHeaderNameAndValue() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();
            config.setAuthHeaderName("Authorization");
            config.setAuthHeaderValue("Bearer token");

            assertThatNoException()
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config));
        }
    }

    @Test
    void shouldAcceptConfigWithoutAuthHeader() {
        try (final var publisherFactory = new WebhookNotificationPublisherFactory()) {
            final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
            final var config = (WebhookNotificationPublisherRuleConfigV1) ruleConfigSpec.defaultConfig();

            assertThatNoException()
                    .isThrownBy(() -> ruleConfigSpec.validator().validate(config));
        }
    }

}
