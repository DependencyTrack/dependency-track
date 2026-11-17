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
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

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
        if (purl == null) {
            return null;
        }

        final String distroQualifier = PurlUtil.getDistroQualifier(purl);
        if (distroQualifier != null) {
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
            if ("rpm".equals(purl.getType()) && "redhat".equalsIgnoreCase(purl.getNamespace())) {
                return RedHatDistribution.of(distroQualifier);
            }
            return null;
        }

        if ("rpm".equals(purl.getType()) && "redhat".equalsIgnoreCase(purl.getNamespace())) {
            return RedHatDistribution.ofRpmRelease(purl.getVersion());
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
            // The Red Hat suffix is a CPE 2.2 URI fragment scoping the RPM to a
            // specific Red Hat product stream, e.g. `rhel_aus:8.4::appstream`.
            // https://ossf.github.io/osv-schema/#defined-ecosystems
            case "red hat" -> RedHatDistribution.ofCpe(suffix);
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

    record DebianDistribution(String series, @Nullable String version) implements OsDistribution {

        // https://debian.pages.debian.net/distro-info-data/debian.csv
        private static final List<DebianDistribution> KNOWN_DISTRIBUTIONS = List.of(
                new DebianDistribution("buzz", "1.1"),
                new DebianDistribution("rex", "1.2"),
                new DebianDistribution("bo", "1.3"),
                new DebianDistribution("hamm", "2.0"),
                new DebianDistribution("slink", "2.1"),
                new DebianDistribution("potato", "2.2"),
                new DebianDistribution("woody", "3.0"),
                new DebianDistribution("sarge", "3.1"),
                new DebianDistribution("etch", "4.0"),
                new DebianDistribution("lenny", "5.0"),
                new DebianDistribution("squeeze", "6.0"),
                new DebianDistribution("wheezy", "7"),
                new DebianDistribution("jessie", "8"),
                new DebianDistribution("stretch", "9"),
                new DebianDistribution("buster", "10"),
                new DebianDistribution("bullseye", "11"),
                new DebianDistribution("bookworm", "12"),
                new DebianDistribution("trixie", "13"),
                new DebianDistribution("forky", "14"),
                new DebianDistribution("duke", "15"),
                new DebianDistribution("sid", null));

        private static final Pattern DEBIAN_SERIES_PATTERN = Pattern.compile("^[A-Za-z]+$");
        private static final Pattern DEBIAN_VERSION_PATTERN = Pattern.compile("^(\\d+)(\\.\\d+)?$");
        private static final Pattern DEBIAN_QUALIFIER_PATTERN =
                Pattern.compile("(?:debian-)?(.+)", Pattern.CASE_INSENSITIVE);

        public DebianDistribution {
            requireNonNull(series, "series must not be null");
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

            return Optional.of(new DebianDistribution(series.toLowerCase(), null));
        }

        private static Optional<DebianDistribution> ofUnknownVersion(@Nullable String version) {
            if (version == null || version.isEmpty() || !DEBIAN_VERSION_PATTERN.matcher(version).matches()) {
                return Optional.empty();
            }

            return Optional.of(new DebianDistribution(version, version));
        }

    }

    record RedHatDistribution(Product product, String majorVersion) implements OsDistribution {

        public enum Product {
            RHEL("redhat"),
            HUMMINGBIRD("hummingbird");

            private final String qualifierPrefix;

            Product(String qualifierPrefix) {
                this.qualifierPrefix = qualifierPrefix;
            }
        }

        private static final Pattern VERSION_PATTERN = Pattern.compile("^(\\d+)(?:\\..*)?$");

        // Finds the `el<N>` Enterprise Linux marker in an RPM release string and
        // captures the RHEL major. The common form is the dist tag that Red Hat's
        // `%{?dist}` macro sets, such as `.el8` or `.el9`, where N is the major version
        // of Enterprise Linux.
        //
        // We also match the same `el<N>` token in Red Hat build conventions that
        // have no formal spec but show up in real RHEL and OSV data:
        //
        // * EUS and z-stream releases (`.el8_6`)
        // * product build suffixes (`.el8sat`)
        // * the modular release marker (`+el8.7.0+...`)
        //
        // Note that only the major version is captured.
        private static final Pattern EL_MARKER_PATTERN = Pattern.compile("(?:^|[.+])el(\\d+)(?:\\.\\d+)?");

        // Finds the `hum<N>` dist tag of Red Hat Hummingbird, e.g. `2.43-8.7.hum1`.
        private static final Pattern HUMMINGBIRD_MARKER_PATTERN = Pattern.compile("\\.hum(\\d+)");

        public RedHatDistribution {
            requireNonNull(product, "product must not be null");
            requireNonNull(majorVersion, "majorVersion must not be null");
        }

        @Override
        public String purlQualifierValue() {
            return product.qualifierPrefix + "-" + majorVersion;
        }

        @Override
        public boolean matches(OsDistribution other) {
            // NB: Hummingbird is a rolling release, so its version does not identify a stream.
            return other instanceof RedHatDistribution(final Product otherProduct, final String otherMajorVersion)
                    && this.product == otherProduct
                    && (this.product == Product.HUMMINGBIRD || this.majorVersion.equals(otherMajorVersion));
        }

        public static @Nullable RedHatDistribution of(@Nullable String qualifierValue) {
            if (qualifierValue == null || qualifierValue.isEmpty()) {
                return null;
            }

            // NB: Some generators emit "rhel-<version>" (e.g. Syft),
            // others "redhat-<version>" (e.g. Trivy).
            final String qualifierValueLower = qualifierValue.toLowerCase();
            final String version;
            if (qualifierValueLower.startsWith("hummingbird-")) {
                return ofVersion(Product.HUMMINGBIRD, qualifierValue.substring("hummingbird-".length()));
            } else if (qualifierValueLower.startsWith("rhel-")) {
                version = qualifierValue.substring("rhel-".length());
            } else if (qualifierValueLower.startsWith("redhat-")) {
                version = qualifierValue.substring("redhat-".length());
            } else {
                version = qualifierValue;
            }

            return ofVersion(version);
        }

        public static @Nullable RedHatDistribution ofVersion(@Nullable String version) {
            return ofVersion(Product.RHEL, version);
        }

        private static @Nullable RedHatDistribution ofVersion(Product product, @Nullable String version) {
            if (version == null || version.isBlank()) {
                return null;
            }

            final Matcher matcher = VERSION_PATTERN.matcher(version);
            if (!matcher.matches()) {
                return null;
            }

            return new RedHatDistribution(product, matcher.group(1));
        }

        public static @Nullable RedHatDistribution ofCpe(@Nullable String cpeSuffix) {
            if (cpeSuffix == null || cpeSuffix.isEmpty()) {
                return null;
            }

            final Cpe cpe;
            try {
                cpe = CpeParser.parse("cpe:/a:redhat:" + cpeSuffix);
            } catch (CpeParsingException e) {
                return null;
            }

            // NB: An explicit "el<N>" OS target in the edition is the same disttag
            // convention used in RPM release strings, so reuse the extractor.
            // It takes precedence over the product version field.
            final RedHatDistribution fromEdition = ofRpmRelease(cpe.getEdition());
            if (fromEdition != null) {
                return fromEdition;
            }

            if (isRhelStreamProduct(cpe.getProduct())) {
                return ofVersion(cpe.getVersion());
            }
            if (cpe.getProduct().equals("hummingbird")) {
                return ofVersion(Product.HUMMINGBIRD, cpe.getVersion());
            }

            return null;
        }

        public static @Nullable RedHatDistribution ofRpmRelease(@Nullable String version) {
            if (version == null || version.isEmpty()) {
                return null;
            }

            final Matcher elMatcher = EL_MARKER_PATTERN.matcher(version);
            if (elMatcher.find()) {
                return new RedHatDistribution(Product.RHEL, elMatcher.group(1));
            }

            final Matcher humMatcher = HUMMINGBIRD_MARKER_PATTERN.matcher(version);
            if (humMatcher.find()) {
                return new RedHatDistribution(Product.HUMMINGBIRD, humMatcher.group(1));
            }

            return null;
        }

        // CPE products whose CPE version field is the RHEL `major(.minor)`. Determined
        // by sampling the OSV Red Hat advisory data. Products not in this list
        // (e.g. `satellite`, `openshift`, `rhel_software_collections`) put their own product
        // version in the version field, so the RHEL major must come from the edition's
        // `el<N>` target instead. Hardcoding the list risks going out of date,
        // but new streams are released very rarely.
        private static boolean isRhelStreamProduct(String product) {
            return product.startsWith("enterprise_linux")
                    || product.equals("rhel_aus")
                    || product.equals("rhel_e4s")
                    || product.equals("rhel_els")
                    || product.equals("rhel_eus")
                    || product.equals("rhel_eus_long_life")
                    || product.equals("rhel_mission_critical")
                    || product.equals("rhel_productivity")
                    || product.equals("rhel_tus")
                    || product.equals("rhel_virtualization")
                    || product.startsWith("rhel_extras");
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

            final Matcher versionMatcher = UBUNTU_VERSION_PATTERN.matcher(version);
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
            if (series == null || series.isEmpty() || !UBUNTU_SERIES_PATTERN.matcher(series).matches()) {
                return Optional.empty();
            }

            return Optional.of(new UbuntuDistribution(series, series));
        }

        private static Optional<UbuntuDistribution> ofUnknownVersion(@Nullable String version) {
            if (version == null || version.isEmpty()) {
                return Optional.empty();
            }

            final Matcher versionMatcher = UBUNTU_VERSION_PATTERN.matcher(version);
            if (!versionMatcher.matches()) {
                return Optional.empty();
            }

            final String majorMinor = versionMatcher.group(1);
            return Optional.of(new UbuntuDistribution(majorMinor, majorMinor));
        }

    }

}
