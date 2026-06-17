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

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import java.util.List;

record SnykIssue(String id, @Nullable String type, Attributes attributes) {

    record Attributes(
            @Nullable String title,
            @Nullable String description,
            @JsonProperty("created_at") @Nullable String createdAt,
            @JsonProperty("updated_at") @Nullable String updatedAt,
            @Nullable List<Problem> problems,
            @Nullable Slots slots,
            @Nullable List<Severity> severities,
            @Nullable List<Coordinate> coordinates) {
    }

    record Problem(String id, String source) {
    }

    record Severity(String source, String level, @Nullable Float score, @Nullable String vector) {
    }

    record Coordinate(@Nullable List<Representation> representations, @Nullable List<Remedy> remedies) {
    }

    record Representation(
            @JsonProperty("resource_path") @Nullable String resourcePath,
            @JsonProperty("package") @Nullable Pkg pkg) {
    }

    record Pkg(@Nullable String url) {
    }

    record Remedy(@Nullable String description) {
    }

    record Slots(
            @Nullable List<Reference> references,
            @JsonProperty("publication_time") @Nullable String publicationTime) {
    }

    record Reference(String url) {
    }

}
