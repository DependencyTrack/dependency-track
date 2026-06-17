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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class NotificationPublishContextTest {

    private final NotificationTemplateRenderer noopTemplateRenderer =
            (notification, additionalContext) -> null;

    @Nested
    class ConstructorTest {

        @Test
        void shouldThrowWhenTemplateRendererIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationPublishContext(null, null))
                    .withMessage("templateRenderer must not be null");
        }

        @Test
        void shouldThrowWhenContactsSupplierIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationPublishContext(null, null, noopTemplateRenderer))
                    .withMessage("ruleContactsSupplier must not be null");
        }

    }

    @Nested
    class ContactsTest {

        @Test
        void shouldReturnSupplierResult() {
            final var contact = new NotificationRuleContact("foo", "foo@example.com");
            final Supplier<Set<NotificationRuleContact>> supplier = () -> Set.of(contact);

            final var context = new NotificationPublishContext(null, supplier, noopTemplateRenderer);

            assertThat(context.ruleContacts()).containsOnly(contact);
        }

        @Test
        void shouldMemoizeSupplierResult() {
            final var supplierInvocationCount = new AtomicInteger(0);
            final Supplier<Set<NotificationRuleContact>> supplier = () -> {
                supplierInvocationCount.incrementAndGet();
                return Collections.emptySet();
            };

            final var context = new NotificationPublishContext(null, supplier, noopTemplateRenderer);

            assertThat(context.ruleContacts()).isEmpty();
            assertThat(context.ruleContacts()).isEmpty();
            assertThat(supplierInvocationCount).hasValue(1);
        }

    }

}