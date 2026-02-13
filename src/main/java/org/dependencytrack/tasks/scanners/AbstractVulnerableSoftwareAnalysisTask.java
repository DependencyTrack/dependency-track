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
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
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
import java.util.Optional;

/**
 * Base analysis task for using the internal VulnerableSoftware model as the source of truth for
 * vulnerability intelligence.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public abstract class AbstractVulnerableSoftwareAnalysisTask extends BaseComponentAnalyzerTask {
    private static final Logger LOGGER = Logger.getLogger(AbstractVulnerableSoftwareAnalysisTask.class);

    /**
     * Analyzes the targetVersion against a list of VulnerableSoftware objects which may contain
     * specific versions or version ranges. For every match, every vulnerability associated with
     * the VulnerableSoftware object will be applied to the specified component.
     *
     * @param qm            the QueryManager to use
     * @param vsList        a list of VulnerableSoftware objects
     * @param targetVersion the version of the component
     * @param component     the component being analyzed
     */
    protected void analyzeVersionRange(final QueryManager qm, final List<VulnerableSoftware> vsList,
            final Cpe targetCpe, final PackageURL targetPURL, final String targetVersion, final Component component,
            final VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        boolean ran = false;
        if (targetCpe != null) {
            analyzeCpeVersionRange(qm, vsList, targetCpe, targetVersion, component, vulnerabilityAnalysisLevel);
            ran = true;
        }
        if (targetPURL != null) {
            analyzePurlVersionRange(qm, vsList, targetPURL, targetVersion, component, vulnerabilityAnalysisLevel);
            ran = true;
        }
        if (!ran) {
            LOGGER.info("Neither CPE nor PURL available for component %s, skipping version range analysis"
                    .formatted(component.getUuid()));
            return;
        }
    }

    protected void analyzePurlVersionRange(final QueryManager qm, final List<VulnerableSoftware> vsList,
            final PackageURL targetPurl, final String targetVersion, final Component component,
            final VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {

        final Version version;
        try {
            version = VersionFactory.forScheme(targetPurl.getType(), targetVersion);
        } catch (InvalidVersionException e) {
            LOGGER.warn("Unable to parse version (" + targetVersion + ") for component (" + component.getUuid() + ")");
            return;
        }
        for (final VulnerableSoftware vs : vsList) {
            if (comparePurlVersions(targetPurl, vs, version)) {
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
            String targetVersion,
            Component component,
            VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs : vsList) {
            final Boolean isCpeMatch = maybeMatchCpe(vs, targetCpe, targetVersion);
            if ((isCpeMatch == null || isCpeMatch) && compareCpeVersions(vs, targetVersion, component)) {
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

    private Boolean maybeMatchCpe(final VulnerableSoftware vs, final Cpe targetCpe, final String targetVersion) {
        if (targetCpe == null || vs.getCpe23() == null) {
            return null;
        }

        final List<Relation> relations = List.of(
                Cpe.compareAttribute(vs.getPart(), toLowerCaseNullable(targetCpe.getPart().getAbbreviation())),
                Cpe.compareAttribute(vs.getVendor(), toLowerCaseNullable(targetCpe.getVendor())),
                Cpe.compareAttribute(vs.getProduct(), toLowerCaseNullable(targetCpe.getProduct())),
                Cpe.compareAttribute(vs.getVersion(), targetVersion),
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
            Logger.getLogger(getClass()).debug("%s: Dropped match with %s due to ambiguous vendor/product relation"
                    .formatted(targetCpe.toCpe23FS(), vs.getCpe23()));
        }

        return isMatch;
    }

    private static boolean comparePurlVersions(PackageURL componentPurl, VulnerableSoftware vs, Version targetVersion) {
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

                if (componentDistro == null || vsDistro == null) {
                    // At least one of the distros could not be identified.
                    // Have to assume they don't match.
                    return false;
                }

                if (!componentDistro.matches(vsDistro)) {
                    // Actual mismatch, e.g. "debian-13" != "sid".
                    return false;
                }
            }
        }

        final Vers vulnerableVersionRange = vs.getVers();

        if (vulnerableVersionRange == null) {
            return false;
        }

        return vs.getVers().contains(targetVersion.toString());
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param vs            a reference to the vulnerable software to compare
     * @param targetVersion the version to compare
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     * <p>
     * Ported from Dependency-Check v5.2.1
     */
    private static boolean compareCpeVersions(VulnerableSoftware vs, String targetVersion, Component component) {
        // Modified from original by @nscuro.
        // Special cases for CPE matching of ANY (*) and NA (*) versions.
        // These don't make sense to use for version range comparison and
        // can be dealt with upfront based on the matching documentation:
        // https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
        if ("*".equals(targetVersion)) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            return true;
        } else if ("-".equals(targetVersion)) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            return "*".equals(vs.getVersion()) || "-".equals(vs.getVersion());
        }

        //if any of the four conditions will be evaluated - then true;
        boolean result = (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty())
                || (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty())
                || (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty())
                || (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty());

        // Modified from original by Steve Springett
        // Added null check: vs.getVersion() != null as purl sources that use version ranges may not have version populated.
        if (!result && vs.getVersion() != null && Cpe.compareAttribute(vs.getVersion(), targetVersion) != Relation.DISJOINT) {
            return true;
        }

        try {
            // If the component has a PURL, we can deduce the applicable versioning scheme from it.
            // TODO: We can probably run some heuristics on targetVersion itself,
            //  e.g. by looking for "deb" or "ubuntu" fragments. But PURL is more reliable.
            final String versioningScheme = Optional
                    .ofNullable(component.getPurl())
                    .flatMap(KnownVersioningSchemes::fromPurl)
                    .orElse(KnownVersioningSchemes.SCHEME_GENERIC);

            final var versBuilder = Vers.builder(versioningScheme);
            if (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, vs.getVersionStartIncluding());
            }
            if (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN, vs.getVersionStartExcluding());
            }
            if (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.LESS_THAN, vs.getVersionEndExcluding());
            }
            if (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, vs.getVersionEndIncluding());
            }

            final Vers vers = versBuilder.build();
            return vers.contains(targetVersion);
        } catch (VersException | InvalidVersionException e) {
            LOGGER.warn("Failed to compare %s against %s".formatted(targetVersion, vs), e);
            return false;
        }
    }

}


