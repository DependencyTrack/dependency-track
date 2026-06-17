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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 4.14.0
 */
public record UbuntuDistribution(String series, String version) implements OsDistribution {

    private static final List<UbuntuDistribution> KNOWN_DISTRIBUTIONS = loadKnownDistributions();
    private static final Pattern SERIES_PATTERN = Pattern.compile("^[A-Za-z]+$");
    private static final Pattern VERSION_PATTERN = Pattern.compile("^(\\d+\\.\\d+)(\\.\\d+)?$");
    private static final Pattern QUALIFIER_PATTERN =
            Pattern.compile("(?:ubuntu-)?(.+)", Pattern.CASE_INSENSITIVE);

    public UbuntuDistribution {
        requireNonNull(series, "series must not be null");
        requireNonNull(version, "version must not be null");
    }

    @Override
    public String purlQualifierValue() {
        return "ubuntu-" + version;
    }

    @Override
    public boolean matches(OsDistribution other) {
        return other instanceof final UbuntuDistribution otherUbuntu
                && this.series.equalsIgnoreCase(otherUbuntu.series);
    }

    public static @Nullable UbuntuDistribution of(@Nullable String qualifierValue) {
        if (qualifierValue == null || qualifierValue.isEmpty()) {
            return null;
        }

        final Matcher matcher = QUALIFIER_PATTERN.matcher(qualifierValue);
        if (!matcher.matches()) {
            return null;
        }

        final String value = matcher.group(1);

        return ofKnownSeries(value)
                .or(() -> ofKnownVersion(value))
                .or(() -> ofUnknownSeries(value))
                .or(() -> ofUnknownVersion(value))
                .orElse(null);
    }

    private static Optional<UbuntuDistribution> ofKnownVersion(@Nullable String version) {
        if (version == null || version.isEmpty()) {
            return Optional.empty();
        }

        final Matcher versionMatcher = VERSION_PATTERN.matcher(version);
        if (!versionMatcher.matches()) {
            return Optional.empty();
        }

        final String majorMinor = versionMatcher.group(1);
        return KNOWN_DISTRIBUTIONS.stream()
                .filter(distro -> distro.version().equals(majorMinor))
                .findAny();
    }

    private static Optional<UbuntuDistribution> ofKnownSeries(@Nullable String series) {
        if (series == null || series.isEmpty()) {
            return Optional.empty();
        }

        return KNOWN_DISTRIBUTIONS.stream()
                .filter(distro -> distro.series().equalsIgnoreCase(series))
                .findAny();
    }

    private static Optional<UbuntuDistribution> ofUnknownSeries(@Nullable String series) {
        if (series == null || series.isEmpty() || !SERIES_PATTERN.matcher(series).matches()) {
            return Optional.empty();
        }

        return Optional.of(new UbuntuDistribution(series, series));
    }

    private static Optional<UbuntuDistribution> ofUnknownVersion(@Nullable String version) {
        if (version == null || version.isEmpty()) {
            return Optional.empty();
        }

        final Matcher versionMatcher = VERSION_PATTERN.matcher(version);
        if (!versionMatcher.matches()) {
            return Optional.empty();
        }

        final String majorMinor = versionMatcher.group(1);
        return Optional.of(new UbuntuDistribution(majorMinor, majorMinor));
    }

    private static List<UbuntuDistribution> loadKnownDistributions() {
        try (final InputStream is = UbuntuDistribution.class.getResourceAsStream("ubuntu.csv")) {
            if (is == null) {
                throw new IllegalStateException("Missing CSV file");
            }

            final List<UbuntuDistribution> distros = new ArrayList<>();
            try (final var isReader = new InputStreamReader(is, StandardCharsets.UTF_8);
                 final var bufferedReader = new BufferedReader(isReader)) {
                final String header = bufferedReader.readLine();
                if (header == null) {
                    throw new IllegalStateException("CSV file is empty");
                }

                final List<String> columns = List.of(header.split(",", -1));
                final int versionIdx = columns.indexOf("version");
                final int seriesIdx = columns.indexOf("series");
                if (versionIdx < 0 || seriesIdx < 0) {
                    throw new IllegalStateException("CSV is missing required columns: " + columns);
                }

                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.isBlank() || line.startsWith("#")) {
                        continue;
                    }

                    final String[] fields = line.split(",", -1);
                    if (fields.length <= Math.max(versionIdx, seriesIdx)) {
                        continue;
                    }

                    final String series = fields[seriesIdx].trim();
                    // Ubuntu CSV encodes LTS releases as "X.YY LTS" in the version column.
                    // Strip the suffix so we keep the bare version number.
                    final String version = fields[versionIdx].trim().replaceFirst("\\s+LTS$", "");
                    if (series.isEmpty() || version.isEmpty()) {
                        continue;
                    }

                    distros.add(new UbuntuDistribution(series, version));
                }
            }

            return List.copyOf(distros);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load CSV file", e);
        }
    }

}
