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
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Represents the result of an individual OpenSSF Scorecard check
 * for a package.
 *
 * @since 5.2.0
 */
@NullMarked
public record PackageHealthScorecardCheck(
        PackageURL purl,
        String name,
        @Nullable String description,
        @Nullable Float score,
        @Nullable String reason,
        List<String> details,
        @Nullable String documentationUrl) {

    public PackageHealthScorecardCheck {
        PurlUtil.requirePackageOnly(requireNonNull(purl, "purl must not be null"));
        requireNonNull(name, "name must not be null");
        requireNonNull(details, "details must not be null");

        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }

        details = List.copyOf(details);
    }
}
