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
package org.dependencytrack.util;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import jakarta.json.Json;
import org.jspecify.annotations.Nullable;

import java.util.TreeMap;
import java.util.regex.Pattern;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

public class PurlUtil {

    private static final Pattern EPOCH_PREFIX_PATTERN = Pattern.compile("^\\d+:");

    private PurlUtil() { }

    public static PackageURL purlCoordinatesOnly(final PackageURL original) throws MalformedPackageURLException {
        return aPackageURL()
                .withType(original.getType())
                .withNamespace(original.getNamespace())
                .withName(original.getName())
                .withVersion(original.getVersion())
                .build();
    }

    public static PackageURL silentPurlCoordinatesOnly(final PackageURL original) {
        if (original == null) {
            return null;
        }
        try {
            return aPackageURL()
                    .withType(original.getType())
                    .withNamespace(original.getNamespace())
                    .withName(original.getName())
                    .withVersion(original.getVersion())
                    .build();
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    /**
     * Attempt to parse a given package URL.
     *
     * @param purl The package URL to parse
     * @return The parsed {@link PackageURL}, or {@code null} when parsing failed
     * @since 4.12.0
     */
    public static PackageURL silentPurl(final String purl) {
        if (purl == null) {
            return null;
        }

        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException ignored) {
            return null;
        }
    }

    public static @Nullable String serializeQualifiers(@Nullable PackageURL purl) {
        if (purl == null || purl.getQualifiers() == null || purl.getQualifiers().isEmpty()) {
            return null;
        }

        // Ensure that we produce deterministic output in case of multiple qualifiers.
        final var orderedQualifiers = new TreeMap<>(purl.getQualifiers());

        final var builder = Json.createObjectBuilder();
        orderedQualifiers.forEach(builder::add);
        return builder.build().toString();
    }

    public static @Nullable String getDistroQualifier(@Nullable PackageURL purl) {
        if (purl == null || purl.getQualifiers() == null || purl.getQualifiers().isEmpty()) {
            return null;
        }

        for (final var qualifier : purl.getQualifiers().entrySet()) {
            if ("distro".equals(qualifier.getKey())) {
                return qualifier.getValue();
            }
        }

        return null;
    }

    /**
     * Returns the PURL's version with any type-specific transformations applied to make it
     * suitable for ecosystem-aware comparison. Returns the raw version when no transformation
     * applies, or {@code null} if no version is set.
     * <p>
     * Applied transformations:
     * <ul>
     *   <li>{@code deb}/{@code rpm}: fold the {@code epoch} qualifier into the version as
     *       {@code <epoch>:<version>} when not already encoded inline.</li>
     * </ul>
     */
    public static @Nullable String getEffectiveVersion(@Nullable PackageURL purl) {
        if (purl == null || purl.getVersion() == null) {
            return null;
        }

        final String version = purl.getVersion();
        final String type = purl.getType();
        if (!PackageURL.StandardTypes.DEBIAN.equals(type)
                && !PackageURL.StandardTypes.RPM.equals(type)) {
            return version;
        }

        if (EPOCH_PREFIX_PATTERN.matcher(version).find()) {
            return version;
        }

        if (purl.getQualifiers() == null) {
            return version;
        }

        final String epoch = purl.getQualifiers().get("epoch");
        if (epoch == null || epoch.isBlank()) {
            return version;
        }

        return epoch + ":" + version;
    }

    public static @Nullable String getDistroQualifier(@Nullable String purl) {
        final PackageURL parsedPurl = silentPurl(purl);
        if (parsedPurl == null) {
            return null;
        }

        return getDistroQualifier(parsedPurl);
    }

}
