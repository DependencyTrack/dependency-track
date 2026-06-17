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
package org.dependencytrack.notification.api;

import org.dependencytrack.notification.proto.v1.Notification;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.notification.api.NotificationFactory.newNotificationBuilder;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_UNSPECIFIED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_UNSPECIFIED;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_UNSPECIFIED;

class NotificationFactoryTest {

    @Test
    void newNotificationBuilderShouldPopulateRequiredFields() {
        final Notification.Builder builder = newNotificationBuilder(
                SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL);
        assertThat(builder.getId()).isNotBlank();
        assertThat(builder.hasTimestamp()).isTrue();
        assertThat(builder.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(builder.getGroup()).isEqualTo(GROUP_BOM_CONSUMED);
        assertThat(builder.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
    }

    @Test
    void newNotificationBuilderShouldThrowWhenScopeIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        null, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL))
                .withMessage("scope must not be null");
    }

    @Test
    void newNotificationBuilderShouldThrowWhenScopeIsInvalid() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        SCOPE_UNSPECIFIED, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL))
                .withMessage("Invalid scope: SCOPE_UNSPECIFIED");
    }

    @Test
    void newNotificationBuilderShouldThrowWhenGroupIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        SCOPE_PORTFOLIO, null, LEVEL_INFORMATIONAL))
                .withMessage("group must not be null");
    }

    @Test
    void newNotificationBuilderShouldThrowWhenGroupIsInvalid() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        SCOPE_PORTFOLIO, GROUP_UNSPECIFIED, LEVEL_INFORMATIONAL))
                .withMessage("Invalid group: GROUP_UNSPECIFIED");
    }

    @Test
    void newNotificationBuilderShouldThrowWhenLevelIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, null))
                .withMessage("level must not be null");
    }

    @Test
    void newNotificationBuilderShouldThrowWhenLevelIsInvalid() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> newNotificationBuilder(
                        SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_UNSPECIFIED))
                .withMessage("Invalid level: LEVEL_UNSPECIFIED");
    }

}