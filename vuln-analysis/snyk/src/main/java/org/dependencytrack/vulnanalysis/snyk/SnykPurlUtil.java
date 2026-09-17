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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * PURL normalization helpers for the Snyk analyzer.
 *
 * @since 5.1.0
 */
final class SnykPurlUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SnykPurlUtil.class);
    private static final String CHECKSUM = "checksum";

    private SnykPurlUtil() {}

    /**
     * Builds the request / cache key for a component PURL.
     * <p>
     * When checksum matching is enabled and the PURL is Maven with a {@code checksum}
     * qualifier, returns the full canonical lowercase PURL (preserving checksum).
     * Otherwise returns lowercase coordinates only (legacy behavior).
     * <p>
     * Checksum-qualified matching is currently limited to Maven because that is the
     * ecosystem Snyk supports for checksum PURL qualifiers; other ecosystems remain
     * coordinates-only even when a checksum qualifier is present.
     */
    static String toSnykRequestPurl(PackageURL purl, boolean checksumMatchingEnabled) {
        if (requiresChecksumMeta(purl, checksumMatchingEnabled)) {
            return purl.canonicalize().toLowerCase();
        }
        return purl.getCoordinates().toLowerCase();
    }

    /**
     * Whether this PURL should use checksum matching and {@code meta.packages} semantics.
     * Limited to Maven per current Snyk API support.
     */
    static boolean requiresChecksumMeta(PackageURL purl, boolean checksumMatchingEnabled) {
        return checksumMatchingEnabled
                && PackageURL.StandardTypes.MAVEN.equals(purl.getType())
                && hasChecksumQualifier(purl);
    }

    static boolean hasChecksumQualifier(PackageURL purl) {
        final Map<String, String> qualifiers = purl.getQualifiers();
        if (qualifiers == null || qualifiers.isEmpty()) {
            return false;
        }
        final String checksum = qualifiers.get(CHECKSUM);
        return checksum != null && !checksum.isBlank();
    }

    /**
     * Normalizes a PURL string for correlating request keys with Snyk {@code meta.packages} map keys.
     * Round-trips through {@link PackageURL} canonicalize so {@code sha1:} and {@code sha1%3A} resolve equally.
     */
    static @Nullable String normalizePurlKey(@Nullable String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        try {
            return new PackageURL(purl).canonicalize().toLowerCase();
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Failed to normalize PURL key '{}'", purl, e);
            return purl.toLowerCase();
        }
    }
}
