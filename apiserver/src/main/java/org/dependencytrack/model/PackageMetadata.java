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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
@NullMarked
public record PackageMetadata(
        PackageURL purl,
        @Nullable String latestVersion,
        @Nullable Instant latestVersionPublishedAt,
        Instant resolvedAt,
        @Nullable String resolvedFrom,
        @Nullable String resolvedBy) {

    public PackageMetadata {
        requireNonNull(purl, "purl must not be null");
        requireNonNull(resolvedAt, "resolvedAt must not be null");
        if (purl.getVersion() != null
                || (purl.getQualifiers() != null && !purl.getQualifiers().isEmpty())
                || purl.getSubpath() != null) {
            throw new IllegalArgumentException(
                    "purl must not contain version, qualifiers, or subpath: " + purl);
        }
    }

}
