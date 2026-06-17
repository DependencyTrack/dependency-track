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
package org.dependencytrack.pkgmetadata.resolution.npm;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * @since 5.0.0
 */
record NpmPackageDocument(
        @Nullable String latestVersion,
        Map<String, VersionInfo> versions) {

    private static final String INTEGRITY_PREFIX = "sha512-";

    @JsonFormat(shape = JsonFormat.Shape.ARRAY)
    record PackageInfo(
            Instant resolvedAt,
            String version) {
    }

    @JsonFormat(shape = JsonFormat.Shape.ARRAY)
    record VersionInfo(
            @Nullable Instant publishedAt,
            @Nullable String shasum,
            @Nullable String integrity) {
    }

    static NpmPackageDocument parseFrom(JsonParser parser) throws IOException {
        // NB: Package documents can be absurdly large for projects with
        // many versions. Angular packages are approaching 4MB, and surely
        // there are worse offenders out there. Most of the data included
        // in those documents is useless to us. Use stream parsing to make
        // this whole procedure less wasteful.

        String latestVersion = null;
        var timestamps = new HashMap<String, Instant>();
        var distInfo = new HashMap<String, VersionInfo>();

        if (parser.nextToken() != JsonToken.START_OBJECT) {
            throw new IOException("Expected start of JSON object");
        }

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String field = parser.currentName();
            parser.nextToken();

            switch (field) {
                case "dist-tags" -> latestVersion = parseDistTags(parser);
                case "time" -> parseTime(parser, timestamps);
                case "versions" -> parseVersions(parser, distInfo);
                default -> parser.skipChildren();
            }
        }

        final var merged = new HashMap<String, VersionInfo>(distInfo.size() + timestamps.size());
        for (final Map.Entry<String, Instant> entry : timestamps.entrySet()) {
            final VersionInfo dist = distInfo.get(entry.getKey());
            if (dist != null) {
                merged.put(entry.getKey(), new VersionInfo(entry.getValue(), dist.shasum(), dist.integrity()));
            } else {
                merged.put(entry.getKey(), new VersionInfo(entry.getValue(), null, null));
            }
        }
        for (final Map.Entry<String, VersionInfo> entry : distInfo.entrySet()) {
            merged.putIfAbsent(entry.getKey(), entry.getValue());
        }

        return new NpmPackageDocument(latestVersion, Map.copyOf(merged));
    }

    private static @Nullable String parseDistTags(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            parser.skipChildren();
            return null;
        }

        String latestVersion = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String tag = parser.currentName();
            parser.nextToken();
            if ("latest".equals(tag)) {
                latestVersion = parser.getText();
            }
        }
        return latestVersion;
    }

    private static void parseTime(JsonParser parser, Map<String, Instant> timestamps) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            parser.skipChildren();
            return;
        }

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String version = parser.currentName();
            parser.nextToken();
            if (version != null && version.contains(".")) {
                try {
                    timestamps.put(version, Instant.parse(parser.getText()));
                } catch (DateTimeParseException _) {
                }
            }
        }
    }

    private static void parseVersions(JsonParser parser, Map<String, VersionInfo> distInfo) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            parser.skipChildren();
            return;
        }

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String version = parser.currentName();
            parser.nextToken();
            distInfo.put(version, parseVersionDist(parser));
        }
    }

    private static VersionInfo parseVersionDist(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            parser.skipChildren();
            return new VersionInfo(null, null, null);
        }

        String shasum = null;
        String integrity = null;

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String field = parser.currentName();
            parser.nextToken();

            if ("dist".equals(field) && parser.currentToken() == JsonToken.START_OBJECT) {
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    final String distField = parser.currentName();
                    parser.nextToken();
                    switch (distField) {
                        case "shasum" -> shasum = parser.getText();
                        case "integrity" -> {
                            final String raw = parser.getText();
                            if (raw != null && raw.startsWith(INTEGRITY_PREFIX)) {
                                integrity = raw.substring(INTEGRITY_PREFIX.length());
                            }
                        }
                        default -> parser.skipChildren();
                    }
                }
            } else {
                parser.skipChildren();
            }
        }

        return new VersionInfo(null, shasum, integrity);
    }

}
