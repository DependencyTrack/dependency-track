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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.NotificationPublisher;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// @since 5.1.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record NotificationPublisherResponse(
        @Schema(description = "Name of the notification publisher", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "Description of the notification publisher")
        @Nullable String description,
        @Schema(description = "Name of the publisher extension that handles delivery", requiredMode = Schema.RequiredMode.REQUIRED)
        String extensionName,
        @Schema(description = "Template used to render the notification payload")
        @Nullable String template,
        @Schema(description = "MIME type of the rendered template", requiredMode = Schema.RequiredMode.REQUIRED)
        String templateMimeType,
        @Schema(description = "Whether the publisher is one of the built-in defaults", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean defaultPublisher,
        @Schema(description = "UUID of the notification publisher", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid) {

    public static NotificationPublisherResponse of(NotificationPublisher publisher) {
        return new NotificationPublisherResponse(
                publisher.getName(),
                publisher.getDescription(),
                publisher.getExtensionName(),
                publisher.getTemplate(),
                publisher.getTemplateMimeType(),
                publisher.isDefaultPublisher(),
                publisher.getUuid());
    }

}
