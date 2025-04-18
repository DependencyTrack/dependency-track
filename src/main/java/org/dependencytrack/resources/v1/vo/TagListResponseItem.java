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

import io.swagger.v3.oas.annotations.media.Schema;

import static io.swagger.v3.oas.annotations.media.Schema.RequiredMode.REQUIRED;

/**
 * @since 4.12.0
 */
public record TagListResponseItem(
        @Schema(description = "Name of the tag", requiredMode = REQUIRED) String name,
        @Schema(description = "Number of projects assigned to this tag", requiredMode = REQUIRED) long projectCount,
        @Schema(description = "Number of collection projects assigned to this tag", requiredMode = REQUIRED) long collectionProjectCount,
        @Schema(description = "Number of policies assigned to this tag", requiredMode = REQUIRED) long policyCount,
        @Schema(description = "Number of notification rules assigned to this tag", requiredMode = REQUIRED) long notificationRuleCount
) {
}
