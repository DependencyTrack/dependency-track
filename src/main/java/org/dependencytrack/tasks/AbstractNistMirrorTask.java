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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.persistence.Transaction;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.Query;
import java.util.Map;

import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

/**
 * @since 4.11.0
 */
abstract class AbstractNistMirrorTask {

    private final Logger logger = Logger.getLogger(getClass());

    Vulnerability synchronizeVulnerability(final QueryManager qm, final Vulnerability vuln) {
        PersistenceUtil.assertNonPersistent(vuln, "vuln must not be persistent");

        return qm.callInTransaction(Transaction.defaultOptions().withSerializeRead(true), () -> {
            Vulnerability persistentVuln = getVulnerabilityByCveId(qm, vuln.getVulnId());
            if (persistentVuln == null) {
                persistentVuln = qm.getPersistenceManager().makePersistent(vuln);
            } else {
                final Map<String, PersistenceUtil.Diff> diffs = updateVulnerability(persistentVuln, vuln);
                if (!diffs.isEmpty()) {
                    logger.debug("%s has changed: %s".formatted(vuln.getVulnId(), diffs));
                    return persistentVuln;
                }

                logger.debug("%s has not changed".formatted(vuln.getVulnId()));
            }

            return persistentVuln;
        });
    }

    /**
     * Get a {@link Vulnerability} by its CVE ID (implying the source {@link Vulnerability.Source#NVD}).
     * <p>
     * It differs from {@link QueryManager#getVulnerabilityByVulnId(String, String)} in that it does not fetch any
     * adjacent relationships (e.g. affected components and aliases).
     *
     * @param qm    The {@link QueryManager} to use
     * @param cveId The CVE ID to look for
     * @return The {@link Vulnerability} matching the CVE ID, or {@code null} when no match was found
     */
    private static Vulnerability getVulnerabilityByCveId(final QueryManager qm, final String cveId) {
        final Query<Vulnerability> query = qm.getPersistenceManager().newQuery(Vulnerability.class);
        query.setFilter("source == :source && vulnId == :cveId");
        query.setNamedParameters(Map.of(
                "source", Vulnerability.Source.NVD.name(),
                "cveId", cveId
        ));
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    /**
     * Update an existing, persistent {@link Vulnerability} with data as reported by the NVD.
     * <p>
     * It differs from {@link QueryManager#updateVulnerability(Vulnerability, boolean)} in that it keeps track of
     * which fields are modified, and assumes the to-be-updated {@link Vulnerability} to be persistent, and enrolled
     * in an active {@link javax.jdo.Transaction}.
     *
     * @param existingVuln The existing {@link Vulnerability} to update
     * @param reportedVuln The {@link Vulnerability} as reported by the NVD
     * @return A {@link Map} holding the differences of all updated fields
     */
    private static Map<String, PersistenceUtil.Diff> updateVulnerability(final Vulnerability existingVuln, final Vulnerability reportedVuln) {
        assertPersistent(existingVuln, "existingVuln must be persistent in order for changes to be effective");

        final var differ = new PersistenceUtil.Differ<>(existingVuln, reportedVuln);
        differ.applyIfChanged("title", Vulnerability::getTitle, existingVuln::setTitle);
        differ.applyIfChanged("subTitle", Vulnerability::getSubTitle, existingVuln::setSubTitle);
        differ.applyIfChanged("description", Vulnerability::getDescription, existingVuln::setDescription);
        differ.applyIfChanged("detail", Vulnerability::getDetail, existingVuln::setDetail);
        differ.applyIfChanged("recommendation", Vulnerability::getRecommendation, existingVuln::setRecommendation);
        differ.applyIfChanged("references", Vulnerability::getReferences, existingVuln::setReferences);
        differ.applyIfChanged("credits", Vulnerability::getCredits, existingVuln::setCredits);
        differ.applyIfChanged("created", Vulnerability::getCreated, existingVuln::setCreated);
        differ.applyIfChanged("published", Vulnerability::getPublished, existingVuln::setPublished);
        differ.applyIfChanged("updated", Vulnerability::getUpdated, existingVuln::setUpdated);
        differ.applyIfNonEmptyAndChanged("cwes", Vulnerability::getCwes, existingVuln::setCwes);
        differ.applyIfChanged("severity", Vulnerability::getSeverity, existingVuln::setSeverity);
        differ.applyIfChanged("cvssV2BaseScore", Vulnerability::getCvssV2BaseScore, existingVuln::setCvssV2BaseScore);
        differ.applyIfChanged("cvssV2ImpactSubScore", Vulnerability::getCvssV2ImpactSubScore, existingVuln::setCvssV2ImpactSubScore);
        differ.applyIfChanged("cvssV2ExploitabilitySubScore", Vulnerability::getCvssV2ExploitabilitySubScore, existingVuln::setCvssV2ExploitabilitySubScore);
        differ.applyIfChanged("cvssV2Vector", Vulnerability::getCvssV2Vector, existingVuln::setCvssV2Vector);
        differ.applyIfChanged("cvssV3BaseScore", Vulnerability::getCvssV3BaseScore, existingVuln::setCvssV3BaseScore);
        differ.applyIfChanged("cvssV3ImpactSubScore", Vulnerability::getCvssV3ImpactSubScore, existingVuln::setCvssV3ImpactSubScore);
        differ.applyIfChanged("cvssV3ExploitabilitySubScore", Vulnerability::getCvssV3ExploitabilitySubScore, existingVuln::setCvssV3ExploitabilitySubScore);
        differ.applyIfChanged("cvssV3Vector", Vulnerability::getCvssV3Vector, existingVuln::setCvssV3Vector);
        differ.applyIfChanged("owaspRRLikelihoodScore", Vulnerability::getOwaspRRLikelihoodScore, existingVuln::setOwaspRRLikelihoodScore);
        differ.applyIfChanged("owaspRRTechnicalImpactScore", Vulnerability::getOwaspRRTechnicalImpactScore, existingVuln::setOwaspRRTechnicalImpactScore);
        differ.applyIfChanged("owaspRRBusinessImpactScore", Vulnerability::getOwaspRRBusinessImpactScore, existingVuln::setOwaspRRBusinessImpactScore);
        differ.applyIfChanged("owaspRRVector", Vulnerability::getOwaspRRVector, existingVuln::setOwaspRRVector);
        differ.applyIfChanged("vulnerableVersions", Vulnerability::getVulnerableVersions, existingVuln::setVulnerableVersions);
        differ.applyIfChanged("patchedVersions", Vulnerability::getPatchedVersions, existingVuln::setPatchedVersions);
        // EPSS is an additional enrichment that no source currently provides natively. We don't want EPSS scores of CVEs to be purged.
        differ.applyIfNonNullAndChanged("epssScore", Vulnerability::getEpssScore, existingVuln::setEpssScore);
        differ.applyIfNonNullAndChanged("epssPercentile", Vulnerability::getEpssPercentile, existingVuln::setEpssPercentile);

        return differ.getDiffs();
    }

}
