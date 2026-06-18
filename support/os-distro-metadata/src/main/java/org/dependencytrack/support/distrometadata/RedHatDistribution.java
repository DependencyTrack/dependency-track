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
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.1.0
 */
public record RedHatDistribution(String majorVersion) implements OsDistribution {

    private static final Pattern VERSION_PATTERN = Pattern.compile("^(\\d+)(?:\\..*)?$");

    /// Finds the `el<N>` Enterprise Linux marker in an RPM release string and
    /// captures the RHEL major. The common form is the dist tag that Red Hat's
    /// `%{?dist}` macro sets, such as `.el8` or `.el9`, where N is the major version
    /// of Enterprise Linux.
    ///
    /// We also match the same `el<N>` token in Red Hat build conventions that
    /// have no formal spec but show up in real RHEL and OSV data:
    ///
    /// * EUS and z-stream releases (`.el8_6`)
    /// * product build suffixes (`.el8sat`)
    /// * the modular release marker (`+el8.7.0+...`)
    ///
    /// Note that only the major version is captured.
    private static final Pattern EL_MARKER_PATTERN = Pattern.compile("(?:^|[.+])el(\\d+)(?:\\.\\d+)?");

    public RedHatDistribution {
        requireNonNull(majorVersion, "majorVersion must not be null");
    }

    @Override
    public String purlQualifierValue() {
        return "redhat-" + majorVersion;
    }

    @Override
    public boolean matches(OsDistribution other) {
        return other instanceof RedHatDistribution(final String otherMajorVersion)
                && this.majorVersion.equals(otherMajorVersion);
    }

    public static @Nullable RedHatDistribution of(@Nullable String qualifierValue) {
        if (qualifierValue == null || qualifierValue.isEmpty()) {
            return null;
        }

        // NB: Some generators emit "rhel-<version>" (e.g. Syft),
        // others "redhat-<version>" (e.g. Trivy).
        final String qualifierValueLower = qualifierValue.toLowerCase();
        final String version;
        if (qualifierValueLower.startsWith("rhel-")) {
            version = qualifierValue.substring("rhel-".length());
        } else if (qualifierValueLower.startsWith("redhat-")) {
            version = qualifierValue.substring("redhat-".length());
        } else {
            version = qualifierValue;
        }

        return ofVersion(version);
    }

    public static @Nullable RedHatDistribution ofVersion(@Nullable String version) {
        if (version == null || version.isBlank()) {
            return null;
        }

        final Matcher matcher = VERSION_PATTERN.matcher(version);
        if (!matcher.matches()) {
            return null;
        }

        return new RedHatDistribution(matcher.group(1));
    }

    public static @Nullable RedHatDistribution ofCpe(@Nullable String cpeSuffix) {
        if (cpeSuffix == null || cpeSuffix.isEmpty()) {
            return null;
        }

        final Cpe cpe;
        try {
            cpe = CpeParser.parse("cpe:/a:redhat:" + cpeSuffix);
        } catch (CpeParsingException _) {
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

        return null;
    }

    public static @Nullable RedHatDistribution ofRpmRelease(@Nullable String version) {
        if (version == null || version.isEmpty()) {
            return null;
        }

        final Matcher matcher = EL_MARKER_PATTERN.matcher(version);
        if (!matcher.find()) {
            return null;
        }

        return new RedHatDistribution(matcher.group(1));
    }

    /// CPE products whose CPE version field is the RHEL `major(.minor)`. Determined
    /// by sampling the OSV Red Hat advisory data. Products not in this list
    /// (e.g. `satellite`, `openshift`, `rhel_software_collections`) put their own product
    /// version in the version field, so the RHEL major must come from the edition's
    /// `el<N>` target instead. Hardcoding the list risks going out of date,
    /// but new streams are released very rarely.
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
