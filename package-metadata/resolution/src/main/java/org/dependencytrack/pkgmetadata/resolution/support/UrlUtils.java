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
package org.dependencytrack.pkgmetadata.resolution.support;

import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.regex.Pattern;

public final class UrlUtils {

    private static final Pattern LEADING_TRAILING_SLASHES = Pattern.compile("^/+|/+$");

    private UrlUtils() {
    }

    public static String join(String base, String... segments) {
        final var sb = new StringBuilder();
        sb.append(trimTrailingSlash(base));
        for (final String segment : segments) {
            sb.append('/').append(encodePathSegment(trimLeadingAndTrailingSlashes(segment)));
        }
        return sb.toString();
    }

    public static String trimTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public static boolean hasSameOrigin(String url, String referenceUrl) {
        final URI target = URI.create(url);
        final URI reference = URI.create(referenceUrl);

        // Restrict same-origin to http(s). Anything else (file, ftp, custom schemes)
        // must never be treated as a trusted origin. Auth headers and other
        // origin-gated decisions depend on this.
        if (!isHttpScheme(target.getScheme()) || !isHttpScheme(reference.getScheme())) {
            return false;
        }

        return equalsIgnoreCaseNullable(target.getScheme(), reference.getScheme())
                && equalsIgnoreCaseNullable(target.getHost(), reference.getHost())
                && effectivePort(target) == effectivePort(reference);
    }

    public static @Nullable String resolve(String baseUrl, String path) {
        if (path.isEmpty()) {
            return null;
        }

        final String[] segments = path.split("/", -1);
        final var normalized = new ArrayDeque<String>();
        for (final String segment : segments) {
            if (segment.isEmpty() || ".".equals(segment)) {
                continue;
            }
            if ("..".equals(segment)) {
                if (normalized.isEmpty()) {
                    return null;
                }
                normalized.removeLast();
            } else {
                normalized.addLast(segment);
            }
        }

        if (normalized.isEmpty()) {
            return null;
        }

        return trimTrailingSlash(baseUrl) + "/" + String.join("/", normalized);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }

        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String trimLeadingAndTrailingSlashes(String value) {
        return LEADING_TRAILING_SLASHES.matcher(value).replaceAll("");
    }

    private static boolean equalsIgnoreCaseNullable(@Nullable String a, @Nullable String b) {
        return (a == null) ? b == null : a.equalsIgnoreCase(b);
    }

    private static String encodePathSegment(String segment) {
        try {
            // The multi-arg URI constructor percent-encodes the path per RFC 3986.
            // It treats '/' as a path separator, so we encode it separately since
            // this method encodes a single segment where '/' is a literal character.
            return new URI(null, null, "/" + segment, null)
                    .getRawPath()
                    .substring(1)
                    .replace("/", "%2F");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid path segment: " + segment, e);
        }
    }

    private static boolean isHttpScheme(@Nullable String scheme) {
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }

}
