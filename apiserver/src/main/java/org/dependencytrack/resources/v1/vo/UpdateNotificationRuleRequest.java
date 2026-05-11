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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.validation.ValidCronExpression;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.jspecify.annotations.Nullable;

import java.util.Set;
import java.util.UUID;

/**
 * @since 5.0.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UpdateNotificationRuleRequest(
        @NotBlank String name,
        boolean enabled,
        boolean notifyChildren,
        boolean logSuccessfulPublish,
        @NotNull NotificationScope scope,
        @JsonAlias("notificationLevel") @NotNull NotificationLevel level,
        Set<@NotNull NotificationGroup> notifyOn,
        String publisherConfig,
        @Size(max = 2048) String filterExpression,
        Set<Tag> tags,
        @NotNull UUID uuid,
        @Nullable @ValidCronExpression String scheduleCron,
        @Nullable Boolean scheduleSkipUnchanged) {
}
