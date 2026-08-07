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
import java.util.Map;

/**
 * Top-level {@code meta} object from Snyk's batch packages/issues response.
 *
 * @since 5.1.0
 */
record SnykIssuesMeta(
        @Nullable List<Error> errors,
        @Nullable Map<String, PackageMetaEntry> packages) {

    /**
     * JSON:API error object from {@code meta.errors}.
     */
    record Error(
            @Nullable String id,
            @Nullable String status,
            @Nullable String detail) {
    }

    /**
     * Per-PURL entry in {@code meta.packages}.
     */
    record PackageMetaEntry(
            @Nullable Match match,
            @JsonProperty("package") @Nullable PackageInfo packageInfo) {
    }

    /**
     * Resolved package identity from {@code meta.packages[].package}.
     */
    record PackageInfo(
            @Nullable String name,
            @Nullable String namespace,
            @Nullable String type,
            @Nullable String url,
            @Nullable String version) {
    }

    /**
     * Match metadata from Snyk's {@code meta.packages[].match} or {@code meta.match}.
     * {@code details.checksum} is {@code null} when no checksum was sent in the request.
     */
    record Match(
            @Nullable SnykMatchType type,
            @Nullable String description,
            @Nullable Details details,
            @Nullable Input input) {

        record Details(
                @JsonProperty("name_version") @Nullable Boolean nameVersion,
                @Nullable Boolean checksum) {
        }

        record Input(
                @Nullable String purl,
                @Nullable String checksum) {
        }
    }

}
