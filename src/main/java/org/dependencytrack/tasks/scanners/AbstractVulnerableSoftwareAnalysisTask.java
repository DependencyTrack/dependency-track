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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.ComponentVersion;
import org.dependencytrack.util.NotificationUtil;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.util.Relation;

import java.util.List;

/**
 * Base analysis task for using the internal VulnerableSoftware model as the source of truth for
 * vulnerability intelligence.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public abstract class AbstractVulnerableSoftwareAnalysisTask extends BaseComponentAnalyzerTask {

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
                                       final Cpe targetCpe, final String targetVersion, final Component component,
                                       final VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs : vsList) {
            final Boolean isCpeMatch = maybeMatchCpe(vs, targetCpe, targetVersion);
            if ((isCpeMatch == null || isCpeMatch) && compareVersions(vs, targetVersion)) {
                if (vs.getVulnerabilities() != null) {
                    for (final Vulnerability vulnerability : vs.getVulnerabilities()) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vulnerability, component, this.getAnalyzerIdentity());
                    }
                }
            }
        }
    }
    
    private Boolean maybeMatchCpe(final VulnerableSoftware vs, final Cpe targetCpe, final String targetVersion) {
        if (targetCpe == null || vs.getCpe23() == null) {
            return null;
        }

        final List<Relation> relations = List.of(
                Cpe.compareAttribute(vs.getPart(), targetCpe.getPart().getAbbreviation()),
                Cpe.compareAttribute(vs.getVendor(), targetCpe.getVendor()),
                Cpe.compareAttribute(vs.getProduct(), targetCpe.getProduct()),
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
    private static boolean compareVersions(VulnerableSoftware vs, String targetVersion) {
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

}
