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

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.util.Relation;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

public final class VulnerableSoftwareMatchUtil {

    private static final Logger LOGGER = Logger.getLogger(VulnerableSoftwareMatchUtil.class);

    private VulnerableSoftwareMatchUtil() {
    }

    public static boolean isAffected(final VulnerableSoftware vs, final Component component) {
        if (vs == null || component == null) {
            return false;
        }

        final String targetVersion = extractComparableVersion(component);
        if (targetVersion == null) {
            return false;
        }

        if (hasPurlIdentity(vs)) {
            return matchesPurl(vs, component) && compareVersions(vs, targetVersion);
        }

        if (hasCpeIdentity(vs)) {
            final Cpe targetCpe = parseCpe(component.getCpe());
            if (targetCpe == null) {
                return false;
            }

            final Boolean cpeMatch = maybeMatchCpe(vs, targetCpe, targetVersion);
            return (cpeMatch == null || cpeMatch) && compareVersions(vs, targetVersion);
        }

        return false;
    }

    public static String extractComparableVersion(final Component component) {
        if (component == null) {
            return null;
        }

        final Cpe parsedCpe = parseCpe(component.getCpe());
        String targetVersion = parsedCpe != null
                ? parsedCpe.getVersion()
                : component.getPurl() != null ? component.getPurl().getVersion() : null;

        if (targetVersion == null) {
            return null;
        }

        return normalizeVersion(targetVersion);
    }

    public static Boolean maybeMatchCpe(final VulnerableSoftware vs, final Cpe targetCpe, final String targetVersion) {
        if (targetCpe == null || vs == null) {
            return null;
        }

        final Cpe sourceCpe = parseCpe(vs.getCpe23() != null ? vs.getCpe23() : vs.getCpe22());

        final List<Relation> relations = List.of(
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getPart().getAbbreviation() : normalizeCpeAttribute(vs.getPart()),
                        toLowerCaseNullable(targetCpe.getPart().getAbbreviation())),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getVendor() : normalizeCpeAttribute(vs.getVendor()),
                        toLowerCaseNullable(targetCpe.getVendor())),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getProduct() : normalizeCpeAttribute(vs.getProduct()),
                        toLowerCaseNullable(targetCpe.getProduct())),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getVersion() : normalizeCpeAttribute(vs.getVersion()), targetVersion),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getUpdate() : normalizeCpeAttribute(vs.getUpdate()), targetCpe.getUpdate()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getEdition() : normalizeCpeAttribute(vs.getEdition()), targetCpe.getEdition()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getLanguage() : normalizeCpeAttribute(vs.getLanguage()), targetCpe.getLanguage()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getSwEdition() : normalizeCpeAttribute(vs.getSwEdition()), targetCpe.getSwEdition()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getTargetSw() : normalizeCpeAttribute(vs.getTargetSw()), targetCpe.getTargetSw()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getTargetHw() : normalizeCpeAttribute(vs.getTargetHw()), targetCpe.getTargetHw()),
                Cpe.compareAttribute(sourceCpe != null ? sourceCpe.getOther() : normalizeCpeAttribute(vs.getOther()), targetCpe.getOther())
        );
        if (relations.contains(Relation.DISJOINT)) {
            return false;
        }

        boolean isMatch = true;

        final Relation vendorRelation = relations.get(1);
        final Relation productRelation = relations.get(2);
        isMatch &= !(vendorRelation == Relation.SUBSET && productRelation == Relation.SUPERSET);
        isMatch &= !(vendorRelation == Relation.SUPERSET && productRelation == Relation.SUBSET);
        if (!isMatch) {
            LOGGER.debug("%s: Dropped match with %s due to ambiguous vendor/product relation"
                    .formatted(targetCpe.toCpe23FS(), vs.getCpe23()));
        }

        return isMatch;
    }

    public static boolean compareVersions(final VulnerableSoftware vs, final String targetVersion) {
        if (vs == null || targetVersion == null) {
            return false;
        }

        if ("*".equals(targetVersion)) {
            return true;
        } else if ("-".equals(targetVersion)) {
            return "*".equals(vs.getVersion()) || "-".equals(vs.getVersion());
        }

        boolean result = (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty())
                || (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty())
                || (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty())
                || (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty());

        if (!result && vs.getVersion() != null && Cpe.compareAttribute(vs.getVersion(), targetVersion) != Relation.DISJOINT) {
            return true;
        }

        final ComponentVersion target = new ComponentVersion(targetVersion);
        if (target.getVersionParts().isEmpty()) {
            return false;
        }
        if (result && vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty()) {
            final ComponentVersion endExcluding = new ComponentVersion(vs.getVersionEndExcluding());
            result = endExcluding.compareTo(target) > 0;
        }
        if (result && vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty()) {
            final ComponentVersion startExcluding = new ComponentVersion(vs.getVersionStartExcluding());
            result = startExcluding.compareTo(target) < 0;
        }
        if (result && vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty()) {
            final ComponentVersion endIncluding = new ComponentVersion(vs.getVersionEndIncluding());
            result &= endIncluding.compareTo(target) >= 0;
        }
        if (result && vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty()) {
            final ComponentVersion startIncluding = new ComponentVersion(vs.getVersionStartIncluding());
            result &= startIncluding.compareTo(target) <= 0;
        }
        return result;
    }

    public static boolean matchesPurl(final VulnerableSoftware vs, final Component component) {
        if (vs == null || component == null || component.getPurl() == null) {
            return false;
        }

        final PackageURL affectedPurl = toIdentityPurl(vs);
        final PackageURL componentPurl = component.getPurl();
        if (affectedPurl == null || componentPurl == null) {
            return false;
        }

        return Objects.equals(normalizeNullable(affectedPurl.getType()), normalizeNullable(componentPurl.getType()))
                && Objects.equals(normalizeNullable(affectedPurl.getNamespace()), normalizeNullable(componentPurl.getNamespace()))
                && Objects.equals(normalizeNullable(affectedPurl.getName()), normalizeNullable(componentPurl.getName()));
    }

    public static boolean hasPurlIdentity(final VulnerableSoftware vs) {
        return vs != null && (vs.getPurl() != null || (vs.getPurlType() != null && vs.getPurlName() != null));
    }

    public static boolean hasCpeIdentity(final VulnerableSoftware vs) {
        return vs != null && (vs.getCpe23() != null || vs.getCpe22() != null
                || (vs.getVendor() != null && vs.getProduct() != null));
    }

    private static String normalizeVersion(final String targetVersion) {
        if (targetVersion == null) {
            return null;
        }

        if (targetVersion.length() > 1 && targetVersion.startsWith("v")) {
            if (targetVersion.matches("v0.0.0-\\d{14}-[a-f0-9]{12}")) {
                return targetVersion.substring(7, 11) + "-" + targetVersion.substring(11, 13) + "-" + targetVersion.substring(13, 15);
            }
            return targetVersion.substring(1);
        }

        return targetVersion;
    }

    private static PackageURL toIdentityPurl(final VulnerableSoftware vs) {
        if (vs.getPurl() != null) {
            try {
                final PackageURL purl = new PackageURL(vs.getPurl());
                return aPackageURL()
                        .withType(purl.getType())
                        .withNamespace(purl.getNamespace())
                        .withName(purl.getName())
                        .build();
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Failed to parse VulnerableSoftware PURL: %s".formatted(vs.getPurl()), e);
                return null;
            }
        }

        if (vs.getPurlType() == null || vs.getPurlName() == null) {
            return null;
        }

        try {
            return aPackageURL()
                    .withType(vs.getPurlType())
                    .withNamespace(vs.getPurlNamespace())
                    .withName(vs.getPurlName())
                    .build();
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Failed to assemble VulnerableSoftware PURL from fields", e);
            return null;
        }
    }

    private static Cpe parseCpe(final String cpeString) {
        if (cpeString == null) {
            return null;
        }

        try {
            return CpeParser.parse(cpeString);
        } catch (CpeParsingException e) {
            LOGGER.debug("Failed to parse component CPE: %s".formatted(cpeString), e);
            return null;
        }
    }

    private static String normalizeNullable(final String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private static String normalizeCpeAttribute(final String value) {
        return value == null ? "*" : value;
    }

    private static String toLowerCaseNullable(final String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }
}
