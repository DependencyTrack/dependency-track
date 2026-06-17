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
package org.dependencytrack.support.distrometadata;

import org.jspecify.annotations.Nullable;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 4.14.0
 */
public record AlpineDistribution(String version) implements OsDistribution {

    private static final Pattern VERSION_PATTERN = Pattern.compile("v?(\\d+\\.\\d+)(?:\\.\\d+)?");

    public AlpineDistribution {
        requireNonNull(version, "version must not be null");
    }

    @Override
    public String purlQualifierValue() {
        return "alpine-" + version;
    }

    @Override
    public boolean matches(OsDistribution other) {
        return other instanceof AlpineDistribution(final String otherVersion)
                && this.version.equals(otherVersion);
    }

    public static @Nullable AlpineDistribution of(@Nullable String qualifierValue) {
        if (qualifierValue == null || qualifierValue.isEmpty()) {
            return null;
        }

        final String version = qualifierValue.toLowerCase().startsWith("alpine-")
                ? qualifierValue.substring(7)
                : qualifierValue;

        return ofVersion(version);
    }

    public static @Nullable AlpineDistribution ofVersion(@Nullable String version) {
        if (version == null || version.isEmpty()) {
            return null;
        }

        final Matcher matcher = VERSION_PATTERN.matcher(version);
        if (!matcher.matches()) {
            return null;
        }

        return new AlpineDistribution(matcher.group(1));
    }

}
