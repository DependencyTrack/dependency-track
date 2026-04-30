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
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.OsDistribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.PurlUtil;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.util.Relation;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Base analysis task for using the internal VulnerableSoftware model as the source of truth for
 * vulnerability intelligence.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public abstract class AbstractVulnerableSoftwareAnalysisTask extends BaseComponentAnalyzerTask {

    private final Logger logger = Logger.getLogger(getClass());

    /**
     * Analyzes the targetVersion against a list of VulnerableSoftware objects which may contain
     * specific versions or version ranges. For every match, every vulnerability associated with
     * the VulnerableSoftware object will be applied to the specified component.
     *
     * @param qm            the QueryManager to use
     * @param vsList        a list of VulnerableSoftware objects
     * @param component     the component being analyzed
     */
    protected void analyzeVersionRange(
            QueryManager qm,
            List<VulnerableSoftware> vsList,
            Cpe targetCpe,
            PackageURL targetPURL,
            Component component,
            VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        boolean ran = false;
        if (targetCpe != null) {
            analyzeCpeVersionRange(qm, vsList, targetCpe, component, vulnerabilityAnalysisLevel);
            ran = true;
        }
        if (targetPURL != null) {
            analyzePurlVersionRange(qm, vsList, targetPURL, component, vulnerabilityAnalysisLevel);
            ran = true;
        }
        if (!ran) {
            logger.info(
                    "Neither CPE nor PURL available for component %s, skipping version range analysis"
                            .formatted(component.getUuid()));
        }
    }

    protected void analyzePurlVersionRange(
            QueryManager qm,
            List<VulnerableSoftware> vsList,
            PackageURL targetPurl,
            Component component,
            VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs : vsList) {
            if (matchesPurl(vs, targetPurl) && comparePurlVersions(targetPurl, vs)) {
                if (vs.getVulnerabilities() != null) {
                    for (final Vulnerability vulnerability : vs.getVulnerabilities()) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component,
                                vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vulnerability, component, this.getAnalyzerIdentity());
                    }
                }
            }
        }
    }

    private void analyzeCpeVersionRange(
            QueryManager qm,
            List<VulnerableSoftware> vsList,
            Cpe targetCpe,
            Component component,
            VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs : vsList) {
            if (matchesCpe(vs, targetCpe) && compareCpeVersions(vs, targetCpe, component)) {
                if (vs.getVulnerabilities() != null) {
                    for (final Vulnerability vulnerability : vs.getVulnerabilities()) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vulnerability, component, this.getAnalyzerIdentity());
                    }
                }
            }
        }
    }

    private static String toLowerCaseNullable(final String string) {
        return string == null ? null : string.toLowerCase();
    }

    private boolean matchesCpe(final VulnerableSoftware vs, final Cpe targetCpe) {
        if (targetCpe == null || vs.getCpe23() == null) {
            return false;
        }

        final List<Relation> relations = List.of(
                Cpe.compareAttribute(vs.getPart(), toLowerCaseNullable(targetCpe.getPart().getAbbreviation())),
                Cpe.compareAttribute(vs.getVendor(), toLowerCaseNullable(targetCpe.getVendor())),
                Cpe.compareAttribute(vs.getProduct(), toLowerCaseNullable(targetCpe.getProduct())),
                Cpe.compareAttribute(vs.getVersion(), targetCpe.getVersion()),
                Cpe.compareAttribute(vs.getUpdate(), targetCpe.getUpdate()),
                Cpe.compareAttribute(vs.getEdition(), targetCpe.getEdition()),
                Cpe.compareAttribute(vs.getLanguage(), targetCpe.getLanguage()),
                Cpe.compareAttribute(vs.getSwEdition(), targetCpe.getSwEdition()),
                Cpe.compareAttribute(vs.getTargetSw(), targetCpe.getTargetSw()),
                Cpe.compareAttribute(vs.getTargetHw(), targetCpe.getTargetHw()),
                Cpe.compareAttribute(vs.getOther(), targetCpe.getOther())
        );
        if (relations.contains(Relation.DISJOINT)) {
            return false;
        }

        boolean isMatch = true;

        // Mixed SUBSET / SUPERSET relations in the vendor and product attribute are prone
        // to false positives: https://github.com/DependencyTrack/dependency-track/issues/3178
        final Relation vendorRelation = relations.get(1);
        final Relation productRelation = relations.get(2);
        isMatch &= !(vendorRelation == Relation.SUBSET && productRelation == Relation.SUPERSET);
        isMatch &= !(vendorRelation == Relation.SUPERSET && productRelation == Relation.SUBSET);
        if (!isMatch) {
            logger.debug("%s: Dropped match with %s due to ambiguous vendor/product relation"
                    .formatted(targetCpe.toCpe23FS(), vs.getCpe23()));
        }

        return isMatch;
    }

    private boolean matchesPurl(VulnerableSoftware vs, PackageURL purl) {
        if (purl == null) {
            return false;
        }

        return Objects.equals(vs.getPurlType(), purl.getType())
                && Objects.equals(vs.getPurlNamespace(), purl.getNamespace())
                && Objects.equals(vs.getPurlName(), purl.getName());
    }

    private boolean comparePurlVersions(PackageURL componentPurl, VulnerableSoftware vs) {
        final String componentVersion = PurlUtil.getEffectiveVersion(componentPurl);
        if (componentVersion == null) {
            return false;
        }

        final String componentDistroQualifier = PurlUtil.getDistroQualifier(componentPurl);
        final String vsDistroQualifier = PurlUtil.getDistroQualifier(vs.getPurl());

        // When both the component and the vulnerable software record have a distro
        // qualifier, they must match *before* we perform the actual version comparison.
        if (componentDistroQualifier != null && vsDistroQualifier != null) {
            // Simplest case: the qualifiers just match without special interpretation.
            if (!componentDistroQualifier.equals(vsDistroQualifier)) {
                // Could still match, but depends on distro semantics.
                // e.g. "debian-13" should match "trixie".
                final var componentDistro = OsDistribution.of(componentPurl);
                final var vsDistro = OsDistribution.of(PurlUtil.silentPurl(vs.getPurl()));

                if (componentDistro != null && vsDistro != null) {
                    if (!componentDistro.matches(vsDistro)) {
                        // Actual mismatch, e.g. "debian-13" != "sid".
                        return false;
                    }
                } else if (componentDistro != null || vsDistro != null) {
                    // One side was parsed, the other wasn't. The raw qualifier
                    // strings already differ, so this is a mismatch.
                    return false;
                } else {
                    // Neither side could be parsed. The raw qualifier strings
                    // already differ, so treat as mismatch to avoid false positives.
                    logger.debug("Neither distro qualifier could be parsed for comparison: %s vs %s"
                            .formatted(componentDistroQualifier, vsDistroQualifier));
                    return false;
                }
            }
        }

        final String versioningScheme = KnownVersioningSchemes.fromPurl(componentPurl)
                .orElse(KnownVersioningSchemes.SCHEME_GENERIC);

        return compareWithVers(vs, componentVersion, versioningScheme);
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param vs            a reference to the vulnerable software to compare
     * @param targetCpe the CPE to compare against
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     * <p>
     * Ported from Dependency-Check v5.2.1
     */
    private boolean compareCpeVersions(VulnerableSoftware vs, Cpe targetCpe, Component component) {
        // Modified from original by @nscuro.
        // Special cases for CPE matching of ANY (*) and NA (*) versions.
        // These don't make sense to use for version range comparison and
        // can be dealt with upfront based on the matching documentation:
        // https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
        if ("*".equals(targetCpe.getVersion())) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            return true;
        } else if ("-".equals(targetCpe.getVersion())) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            return "*".equals(vs.getVersion()) || "-".equals(vs.getVersion());
        }

        boolean result = vs.hasVersionRange();

        // Modified from original by Steve Springett
        // Added null check: vs.getVersion() != null as purl sources that use version ranges may not have version populated.
        if (!result && vs.getVersion() != null && Cpe.compareAttribute(vs.getVersion(), targetCpe.getVersion()) != Relation.DISJOINT) {
            return true;
        }

        // If the component has a PURL, we can deduce the applicable versioning scheme from it.
        final String versioningScheme = Optional
                .ofNullable(component.getPurl())
                .flatMap(KnownVersioningSchemes::fromPurl)
                .orElse(KnownVersioningSchemes.SCHEME_GENERIC);

        return compareWithVers(vs, targetCpe.getVersion(), versioningScheme);
    }

    private boolean compareWithVers(VulnerableSoftware vs, String targetVersion, String versioningScheme) {
        try {
            return buildVers(vs, versioningScheme).contains(targetVersion);
        } catch (VersException | InvalidVersionException e) {
            // NB: We don't log the full exception in any of the error cases,
            // because they would lead to extremely noisy logs.

            // It's always possible that versatile has a bug, or components / vulnerabilities
            // do not strictly follow versioning schemes. Fall back to generic scheme
            // to prevent false negatives.
            if (!KnownVersioningSchemes.SCHEME_GENERIC.equals(versioningScheme)) {
                logger.warn("""
                        Failed to compare %s against %s with scheme %s: %s; \
                        Retrying with scheme %s""".formatted(targetVersion, vs, versioningScheme, e.getMessage(), KnownVersioningSchemes.SCHEME_GENERIC));
                try {
                    return buildVers(vs, KnownVersioningSchemes.SCHEME_GENERIC).contains(targetVersion);
                } catch (VersException | InvalidVersionException e2) {
                    logger.warn("Failed to compare %s against %s with fallback: %s".formatted(targetVersion, vs, e2.getMessage()));
                }
            } else {
                logger.warn("Failed to compare %s against %s: %s".formatted(targetVersion, vs, e.getMessage()));
            }

            return false;
        }
    }

    private static Vers buildVers(VulnerableSoftware vs, String versioningScheme) {
        final var versBuilder = Vers.builder(versioningScheme);

        if (!vs.hasVersionRange()) {
            final String vsVersion = vs.getVersion();
            if (vsVersion == null || vsVersion.isBlank()) {
                versBuilder.withConstraint(Comparator.WILDCARD, null);
            } else {
                versBuilder.withConstraint(Comparator.EQUAL, vsVersion);
            }
        } else {
            if (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isBlank()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, vs.getVersionStartIncluding());
            }
            if (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isBlank()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN, vs.getVersionStartExcluding());
            }
            if (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isBlank()) {
                versBuilder.withConstraint(Comparator.LESS_THAN, vs.getVersionEndExcluding());
            }
            if (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isBlank()) {
                versBuilder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, vs.getVersionEndIncluding());
            }
        }

        return versBuilder.build();
    }

}


