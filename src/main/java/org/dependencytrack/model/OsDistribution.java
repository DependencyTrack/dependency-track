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
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 4.14.0
 */
public sealed interface OsDistribution {

    String purlQualifierValue();

    boolean matches(OsDistribution other);

    static @Nullable OsDistribution of(@Nullable PackageURL purl) {
        final String distroQualifier = PurlUtil.getDistroQualifier(purl);
        if (distroQualifier == null) {
            return null;
        }

        if ("apk".equals(purl.getType())) {
            return AlpineDistribution.of(distroQualifier);
        }

        if ("deb".equals(purl.getType())) {
            if ("debian".equalsIgnoreCase(purl.getNamespace())) {
                return DebianDistribution.of(distroQualifier).orElse(null);
            }
            if ("ubuntu".equalsIgnoreCase(purl.getNamespace())) {
                return UbuntuDistribution.of(distroQualifier).orElse(null);
            }
        }

        return null;
    }

    static @Nullable OsDistribution ofOsvEcosystem(@Nullable String ecosystem) {
        if (ecosystem == null || ecosystem.isEmpty()) {
            return null;
        }

        final int colonIndex = ecosystem.indexOf(':');
        if (colonIndex == -1 || colonIndex == ecosystem.length() - 1) {
            return null;
        }

        final String ecosystemName = ecosystem.substring(0, colonIndex);
        final String suffix = ecosystem.substring(colonIndex + 1);

        return switch (ecosystemName.toLowerCase()) {
            case "alpine" -> AlpineDistribution.ofVersion(suffix);
            case "debian" -> DebianDistribution.of(suffix).orElse(null);
            case "ubuntu" -> {
                // Remove :LTS and :Pro variants. This is in line with what OSV does:
                // https://github.com/google/osv.dev/blob/60cf1d74ec77a8f40589d2bbb3cfd241a545f807/osv/ecosystems/_ecosystems.py#L154-L160
                final String versionOrSeries = suffix.replaceAll(":(LTS|Pro)", "");
                yield UbuntuDistribution.of(versionOrSeries).orElse(null);
            }
            default -> null;
        };
    }

    record AlpineDistribution(String version) implements OsDistribution {

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

        private static @Nullable AlpineDistribution of(@Nullable String qualifierValue) {
            if (qualifierValue == null || qualifierValue.isEmpty()) {
                return null;
            }

            final String version = qualifierValue.toLowerCase().startsWith("alpine-")
                    ? qualifierValue.substring(7)
                    : qualifierValue;

            return ofVersion(version);
        }

        private static @Nullable AlpineDistribution ofVersion(@Nullable String version) {
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

    record DebianDistribution(String codeName, String series, @Nullable String version) implements OsDistribution {

        // https://debian.pages.debian.net/distro-info-data/debian.csv
        private static final List<DebianDistribution> KNOWN_DISTRIBUTIONS = List.of(
                new DebianDistribution("Buzz", "1.1"),
                new DebianDistribution("Rex", "1.2"),
                new DebianDistribution("Bo", "1.3"),
                new DebianDistribution("Hamm", "2.0"),
                new DebianDistribution("Slink", "2.1"),
                new DebianDistribution("Potato", "2.2"),
                new DebianDistribution("Woody", "3.0"),
                new DebianDistribution("Sarge", "3.1"),
                new DebianDistribution("Etch", "4.0"),
                new DebianDistribution("Lenny", "5.0"),
                new DebianDistribution("Squeeze", "6.0"),
                new DebianDistribution("Wheezy", "7"),
                new DebianDistribution("Jessie", "8"),
                new DebianDistribution("Stretch", "9"),
                new DebianDistribution("Buster", "10"),
                new DebianDistribution("Bullseye", "11"),
                new DebianDistribution("Bookworm", "12"),
                new DebianDistribution("Trixie", "13"),
                new DebianDistribution("Forky", "14"),
                new DebianDistribution("Sid", null));

        private static final Pattern DEBIAN_SERIES_PATTERN = Pattern.compile("^[A-Za-z]+$");
        private static final Pattern DEBIAN_VERSION_PATTERN = Pattern.compile("^(\\d+)(\\.\\d+)?$");
        private static final Pattern DEBIAN_QUALIFIER_PATTERN =
                Pattern.compile("(?:debian-)?(.+)", Pattern.CASE_INSENSITIVE);

        public DebianDistribution {
            requireNonNull(codeName, "codeName must not be null");
        }

        private DebianDistribution(String codeName, @Nullable String version) {
            this(codeName, codeName.toLowerCase(), version);
        }

        @Override
        public String purlQualifierValue() {
            return "debian-" + (version != null ? version : series);
        }

        @Override
        public boolean matches(OsDistribution other) {
            return other instanceof final DebianDistribution otherDebian
                    && this.series.equalsIgnoreCase(otherDebian.series);
        }

        private static Optional<DebianDistribution> of(@Nullable String qualifierValue) {
            if (qualifierValue == null || qualifierValue.isEmpty()) {
                return Optional.empty();
            }

            final Matcher matcher = DEBIAN_QUALIFIER_PATTERN.matcher(qualifierValue);
            if (!matcher.matches()) {
                return Optional.empty();
            }

            final String value = matcher.group(1);

            return ofKnownSeries(value)
                    .or(() -> ofKnownVersion(value))
                    .or(() -> ofUnknownSeries(value))
                    .or(() -> ofUnknownVersion(value));
        }

        private static Optional<DebianDistribution> ofKnownVersion(@Nullable String version) {
            if (version == null || version.isEmpty()) {
                return Optional.empty();
            }

            for (final var distro : KNOWN_DISTRIBUTIONS) {
                if (distro.version() == null) {
                    continue;
                }
                if (distro.version().equals(version)) {
                    return Optional.of(distro);
                }
            }

            if (version.contains(".")) {
                final String inputMajor = version.substring(0, version.indexOf('.'));
                for (final var distro : KNOWN_DISTRIBUTIONS) {
                    if (distro.version() == null) {
                        continue;
                    }
                    if (!distro.version().contains(".") && distro.version().equals(inputMajor)) {
                        return Optional.of(distro);
                    }
                }
            }

            return Optional.empty();
        }

        private static Optional<DebianDistribution> ofKnownSeries(@Nullable String series) {
            if (series == null || series.isEmpty()) {
                return Optional.empty();
            }

            return KNOWN_DISTRIBUTIONS.stream()
                    .filter(distro -> distro.series().equalsIgnoreCase(series))
                    .findAny();
        }

        private static Optional<DebianDistribution> ofUnknownSeries(@Nullable String series) {
            if (series == null || series.isEmpty() || !DEBIAN_SERIES_PATTERN.matcher(series).matches()) {
                return Optional.empty();
            }

            return Optional.of(new DebianDistribution(series, series));
        }

        private static Optional<DebianDistribution> ofUnknownVersion(@Nullable String version) {
            if (version == null || version.isEmpty() || !DEBIAN_VERSION_PATTERN.matcher(version).matches()) {
                return Optional.empty();
            }

            return Optional.of(new DebianDistribution(version, version));
        }

    }

    record UbuntuDistribution(String series, String version) implements OsDistribution {

        // https://debian.pages.debian.net/distro-info-data/ubuntu.csv
        private static final List<UbuntuDistribution> KNOWN_DISTRIBUTIONS = List.of(
                new UbuntuDistribution("warty", "4.10"),
                new UbuntuDistribution("hoary", "5.04"),
                new UbuntuDistribution("breezy", "5.10"),
                new UbuntuDistribution("dapper", "6.06"),
                new UbuntuDistribution("edgy", "6.10"),
                new UbuntuDistribution("feisty", "7.04"),
                new UbuntuDistribution("gutsy", "7.10"),
                new UbuntuDistribution("hardy", "8.04"),
                new UbuntuDistribution("intrepid", "8.10"),
                new UbuntuDistribution("jaunty", "9.04"),
                new UbuntuDistribution("karmic", "9.10"),
                new UbuntuDistribution("lucid", "10.04"),
                new UbuntuDistribution("maverick", "10.10"),
                new UbuntuDistribution("natty", "11.04"),
                new UbuntuDistribution("oneiric", "11.10"),
                new UbuntuDistribution("precise", "12.04"),
                new UbuntuDistribution("quantal", "12.10"),
                new UbuntuDistribution("raring", "13.04"),
                new UbuntuDistribution("saucy", "13.10"),
                new UbuntuDistribution("trusty", "14.04"),
                new UbuntuDistribution("utopic", "14.10"),
                new UbuntuDistribution("vivid", "15.04"),
                new UbuntuDistribution("wily", "15.10"),
                new UbuntuDistribution("xenial", "16.04"),
                new UbuntuDistribution("yakkety", "16.10"),
                new UbuntuDistribution("zesty", "17.04"),
                new UbuntuDistribution("artful", "17.10"),
                new UbuntuDistribution("bionic", "18.04"),
                new UbuntuDistribution("cosmic", "18.10"),
                new UbuntuDistribution("disco", "19.04"),
                new UbuntuDistribution("eoan", "19.10"),
                new UbuntuDistribution("focal", "20.04"),
                new UbuntuDistribution("groovy", "20.10"),
                new UbuntuDistribution("hirsute", "21.04"),
                new UbuntuDistribution("impish", "21.10"),
                new UbuntuDistribution("jammy", "22.04"),
                new UbuntuDistribution("kinetic", "22.10"),
                new UbuntuDistribution("lunar", "23.04"),
                new UbuntuDistribution("mantic", "23.10"),
                new UbuntuDistribution("noble", "24.04"),
                new UbuntuDistribution("oracular", "24.10"),
                new UbuntuDistribution("plucky", "25.04"),
                new UbuntuDistribution("questing", "25.10"),
                new UbuntuDistribution("resolute", "26.04"));

        private static final Pattern UBUNTU_SERIES_PATTERN = Pattern.compile("^[A-Za-z]+$");
        private static final Pattern UBUNTU_VERSION_PATTERN = Pattern.compile("^(\\d+\\.\\d+)(\\.\\d+)?$");
        private static final Pattern UBUNTU_QUALIFIER_PATTERN =
                Pattern.compile("(?:ubuntu-)?(.+)", Pattern.CASE_INSENSITIVE);

        public UbuntuDistribution {
            requireNonNull(series, "series must not be null");
            requireNonNull(version, "version must not be null");
        }

        @Override
        public String purlQualifierValue() {
            return "ubuntu-" + (version != null ? version : series);
        }

        @Override
        public boolean matches(OsDistribution other) {
            return other instanceof final UbuntuDistribution otherUbuntu
                    && this.series.equalsIgnoreCase(otherUbuntu.series);
        }

        private static Optional<UbuntuDistribution> of(@Nullable String qualifierValue) {
            if (qualifierValue == null || qualifierValue.isEmpty()) {
                return Optional.empty();
            }

            final Matcher matcher = UBUNTU_QUALIFIER_PATTERN.matcher(qualifierValue);
            if (!matcher.matches()) {
                return Optional.empty();
            }

            final String value = matcher.group(1);

            return ofKnownSeries(value)
                    .or(() -> ofKnownVersion(value))
                    .or(() -> ofUnknownSeries(value))
                    .or(() -> ofUnknownVersion(value));
        }

        private static Optional<UbuntuDistribution> ofKnownVersion(@Nullable String version) {
            if (version == null || version.isEmpty()) {
                return Optional.empty();
            }

            return KNOWN_DISTRIBUTIONS.stream()
                    .filter(distro -> distro.version().equals(version))
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
            if (series == null || series.isEmpty() || !UBUNTU_SERIES_PATTERN.matcher(series).matches()) {
                return Optional.empty();
            }

            return Optional.of(new UbuntuDistribution(series, series));
        }

        private static Optional<UbuntuDistribution> ofUnknownVersion(@Nullable String version) {
            if (version == null || version.isEmpty() || !UBUNTU_VERSION_PATTERN.matcher(version).matches()) {
                return Optional.empty();
            }

            return Optional.of(new UbuntuDistribution(version, version));
        }

    }

}
