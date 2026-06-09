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
 * Models a Red Hat product stream as scoped by the RHEL major version.
 * <p>
 * Component PURLs carry the distro as a {@code distro} qualifier (e.g.
 * {@code pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7}), whereas OSV
 * advisories encode the product stream in the ecosystem string via a
 * {@code :<CPE>} suffix (e.g. {@code Red Hat:rhel_aus:8.4::appstream}). Both forms
 * carry a RHEL major version, which is the smallest reliably comparable scope:
 * an advisory for RHEL 8 must not be matched against a RHEL 9 component.
 *
 * @since 4.14.0
 */
public record RedhatDistribution(String majorVersion) implements OsDistribution {

    // The RHEL OS target embedded in a CPE's version-of-target field, e.g.
    // "el8" in "openshift:4.18::el8" or "satellite:6.16::el8". This is the
    // authoritative OS scope and takes precedence over a product version that
    // happens to differ from the RHEL major (OpenShift 4.18 runs on RHEL 8).
    private static final Pattern EL_TARGET_PATTERN =
            Pattern.compile(".*\\bel(\\d+)\\b.*", Pattern.CASE_INSENSITIVE);

    // The major version of a base RHEL product itself, e.g. "8" in
    // "rhel:8::appstream" or "rhel_aus:8.4::appstream". Used only when the product
    // is a base RHEL stream whose version IS the RHEL major, and no explicit "elN"
    // target is present. Deliberately excludes layered products (e.g.
    // "rhel_application_stack:2", "rhel_atomic:7"), whose version is a product
    // stream number rather than the RHEL major.
    private static final Pattern RHEL_PRODUCT_PATTERN =
            Pattern.compile("^(?:rhel|rhel_aus|rhel_eus|rhel_els|rhel_tus|rhel_e4s|enterprise_linux):(\\d+)(?:[.:].*)?$",
                    Pattern.CASE_INSENSITIVE);

    // The leading major version of a PURL "distro" qualifier value, e.g. "9" in
    // "redhat-9.7" or "9.7". PURL qualifiers carry a bare RHEL version, not a CPE.
    private static final Pattern PURL_VERSION_PATTERN =
            Pattern.compile("^(\\d+)(?:\\..*)?$");

    public RedhatDistribution {
        requireNonNull(majorVersion, "majorVersion must not be null");
    }

    @Override
    public String purlQualifierValue() {
        return "redhat-" + majorVersion;
    }

    @Override
    public boolean matches(OsDistribution other) {
        return other instanceof RedhatDistribution(final String otherMajorVersion)
                && this.majorVersion.equals(otherMajorVersion);
    }

    /**
     * Resolves a Red Hat distro from a PURL {@code distro} qualifier value,
     * e.g. {@code redhat-9.7} or {@code 9.7}.
     */
    public static @Nullable RedhatDistribution of(@Nullable String qualifierValue) {
        if (qualifierValue == null || qualifierValue.isEmpty()) {
            return null;
        }

        final String value = qualifierValue.toLowerCase().startsWith("redhat-")
                ? qualifierValue.substring("redhat-".length())
                : qualifierValue;

        final Matcher matcher = PURL_VERSION_PATTERN.matcher(value);
        if (!matcher.matches()) {
            return null;
        }

        return new RedhatDistribution(matcher.group(1));
    }

    /**
     * Resolves a Red Hat distro from the {@code <CPE>} suffix of an OSV
     * Red Hat ecosystem string. The string is a CPE with the
     * {@code cpe:/[oa]:redhat:} prefix removed, e.g. {@code rhel_aus:8.4::appstream},
     * {@code openshift:4.18::el8}, or {@code satellite:6.16::el8}.
     * <p>
     * An explicit {@code elN} OS target (when present) is authoritative, since a
     * product's own version (OpenShift 4.18, Satellite 6.16) is not the RHEL major.
     * Otherwise the version is taken from a RHEL-family product
     * ({@code rhel*}, {@code enterprise_linux}). Non-RHEL products without an
     * {@code elN} target cannot be scoped to a RHEL major and return {@code null}.
     */
    public static @Nullable RedhatDistribution ofCpe(@Nullable String cpe) {
        if (cpe == null || cpe.isEmpty()) {
            return null;
        }

        final Matcher elMatcher = EL_TARGET_PATTERN.matcher(cpe);
        if (elMatcher.matches()) {
            return new RedhatDistribution(elMatcher.group(1));
        }

        final Matcher productMatcher = RHEL_PRODUCT_PATTERN.matcher(cpe);
        if (productMatcher.matches()) {
            return new RedhatDistribution(productMatcher.group(1));
        }

        return null;
    }

}
