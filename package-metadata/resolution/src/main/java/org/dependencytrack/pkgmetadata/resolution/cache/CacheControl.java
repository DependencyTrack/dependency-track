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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.jspecify.annotations.Nullable;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;

/**
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9111.html#name-cache-control">RFC 9111 - Cache Control</a>
 * @since 5.0.0
 */
record CacheControl(boolean noStore, boolean noCache, @Nullable Long maxAgeSeconds) {

    static final CacheControl ABSENT = new CacheControl(false, false, null);

    static CacheControl of(HttpResponse<?> response) {
        return of(response.headers().allValues("Cache-Control"));
    }

    static CacheControl of(List<String> headerValues) {
        if (headerValues.isEmpty()) {
            return ABSENT;
        }

        boolean noStore = false;
        boolean noCache = false;
        Long maxAge = null;

        for (final String value : headerValues) {
            for (final String token : value.split(",")) {
                final String trimmed = token.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }

                final int equalsIndex = trimmed.indexOf('=');
                final String name = (equalsIndex < 0 ? trimmed : trimmed.substring(0, equalsIndex)).toLowerCase(Locale.ROOT);

                switch (name) {
                    case "no-store" -> noStore = true;
                    case "no-cache" -> noCache = true;
                    case "max-age" -> {
                        final Long parsed = parseMaxAge(
                                equalsIndex >= 0
                                        ? trimmed.substring(equalsIndex + 1).trim()
                                        : null);
                        if (parsed != null) {
                            maxAge = parsed;
                        }
                    }
                    default -> {
                        // Unknown directive.
                    }
                }
            }
        }

        return new CacheControl(noStore, noCache, maxAge);
    }

    private static @Nullable Long parseMaxAge(@Nullable String arg) {
        if (arg == null) {
            return null;
        }

        final String unquoted = arg.length() >= 2 && arg.charAt(0) == '"' && arg.charAt(arg.length() - 1) == '"'
                ? arg.substring(1, arg.length() - 1)
                : arg;
        try {
            final long parsed = Long.parseLong(unquoted);
            return parsed >= 0 ? parsed : null;
        } catch (NumberFormatException ignored) {
            // Treat as absent as per RFC 9111.
            return null;
        }
    }

}
