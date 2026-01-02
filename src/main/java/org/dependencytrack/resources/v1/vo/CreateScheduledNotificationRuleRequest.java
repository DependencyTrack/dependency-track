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

import alpine.common.validation.RegexSequence;
import alpine.notification.NotificationLevel;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.dependencytrack.notification.NotificationScope;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.UUID;

/**
 * @since 4.13.0
 */
public record CreateScheduledNotificationRuleRequest(
        @NotBlank
        @Size(min = 1, max = 255)
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Pattern(
                regexp = RegexSequence.Definition.PRINTABLE_CHARS,
                message = "The name may only contain printable characters")
        String name,
        @NotNull NotificationScope scope,
        @NotNull NotificationLevel notificationLevel,
        @NotNull @Valid Publisher publisher) {

    public record Publisher(@NotNull UUID uuid) {
    }

}
