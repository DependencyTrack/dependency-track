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
package org.dependencytrack.vulnanalysis.snyk;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.jspecify.annotations.Nullable;

/**
 * Match quality reported by Snyk's {@code meta.packages[].match.type} for checksum-qualified PURLs.
 *
 * @since 5.1.0
 */
enum SnykMatchType {
    FULL,
    PARTIAL,
    NONE;

    @JsonValue
    String jsonValue() {
        return name().toLowerCase();
    }

    @JsonCreator
    static @Nullable SnykMatchType fromJson(@Nullable String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return switch (value.toLowerCase()) {
            case "full" -> FULL;
            case "partial" -> PARTIAL;
            case "none" -> NONE;
            default -> null;
        };
    }
}
