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
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.stream.Collectors.groupingBy;
import static org.dependencytrack.util.PersistenceUtil.assertNonPersistentAll;
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

    void synchronizeVulnerableSoftware(final QueryManager qm, final Vulnerability persistentVuln, final List<VulnerableSoftware> vsList) {
        assertPersistent(persistentVuln, "vuln must be persistent");
        assertNonPersistentAll(vsList, "vsList must not be persistent");

        qm.runInTransaction(() -> {
            // Get all VulnerableSoftware records that are currently associated with the vulnerability.
            // Note: For SOME ODD REASON, duplicate (as in, same database ID and all) VulnerableSoftware
            // records are returned, when operating on data that was originally created by the feed-based
            // NistMirrorTask. We thus have to deduplicate here.
            final List<VulnerableSoftware> vsOldList = persistentVuln.getVulnerableSoftware().stream().distinct().toList();
            logger.trace("%s: Existing VS: %d".formatted(persistentVuln.getVulnId(), vsOldList.size()));

            // Get attributions for all existing VulnerableSoftware records.
            final Map<Long, List<AffectedVersionAttribution>> attributionsByVsId =
                    qm.getAffectedVersionAttributions(persistentVuln, vsOldList).stream()
                            .collect(groupingBy(attribution -> attribution.getVulnerableSoftware().getId()));
            for (final VulnerableSoftware vsOld : vsOldList) {
                vsOld.setAffectedVersionAttributions(attributionsByVsId.get(vsOld.getId()));
            }

            // Based on the lists of currently reported, and previously reported VulnerableSoftware records,
            // divide the previously reported ones into lists of records to keep, and records to remove.
            // Records to keep are removed from vsList. Remaining records in vsList thus are entirely new.
            final var vsListToRemove = new ArrayList<VulnerableSoftware>();
            final var vsListToKeep = new ArrayList<VulnerableSoftware>();
            for (final VulnerableSoftware vsOld : vsOldList) {
                if (vsList.removeIf(vsOld::equalsIgnoringDatastoreIdentity)) {
                    vsListToKeep.add(vsOld);
                } else {
                    final List<AffectedVersionAttribution> attributions = vsOld.getAffectedVersionAttributions();
                    if (attributions == null || attributions.isEmpty()) {
                        // DT versions prior to 4.7.0 did not record attributions.
                        // Drop the VulnerableSoftware for now. If it was previously
                        // reported by another source, it will be recorded and attributed
                        // whenever that source is mirrored again.
                        vsListToRemove.add(vsOld);
                        continue;
                    }

                    final boolean previouslyReportedByNvd = attributions.stream()
                            .anyMatch(attr -> attr.getSource() == Vulnerability.Source.NVD);
                    final boolean previouslyReportedByOthers = !previouslyReportedByNvd;

                    if (previouslyReportedByOthers) {
                        vsListToKeep.add(vsOld);
                    } else {
                        vsListToRemove.add(vsOld);
                    }
                }
            }
            logger.trace("%s: vsListToKeep: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            logger.trace("%s: vsListToRemove: %d".formatted(persistentVuln.getVulnId(), vsListToRemove.size()));

            // Remove attributions for VulnerableSoftware records that are no longer reported.
            if (!vsListToRemove.isEmpty()) {
                qm.deleteAffectedVersionAttributions(persistentVuln, vsListToRemove, Vulnerability.Source.NVD);
            }

            final var attributionDate = new Date();

            // For VulnerableSoftware records that existed before, update the lastSeen timestamp.
            for (final VulnerableSoftware oldVs : vsListToKeep) {
                oldVs.getAffectedVersionAttributions().stream()
                        .filter(attribution -> attribution.getSource() == Vulnerability.Source.NVD)
                        .findAny()
                        .ifPresent(attribution -> attribution.setLastSeen(attributionDate));
            }

            // For VulnerableSoftware records that are newly reported for this vulnerability, check if any matching
            // records exist in the database that are currently associated with other (or no) vulnerabilities.
            for (final VulnerableSoftware vs : vsList) {
                final VulnerableSoftware existingVs = qm.getVulnerableSoftwareByCpe23(
                        vs.getCpe23(),
                        vs.getVersionEndExcluding(),
                        vs.getVersionEndIncluding(),
                        vs.getVersionStartExcluding(),
                        vs.getVersionStartIncluding()
                );
                if (existingVs != null) {
                    final boolean hasAttribution = qm.hasAffectedVersionAttribution(persistentVuln, existingVs, Vulnerability.Source.NVD);
                    if (!hasAttribution) {
                        logger.trace("%s: Adding attribution".formatted(persistentVuln.getVulnId()));
                        final AffectedVersionAttribution attribution = createAttribution(persistentVuln, existingVs, attributionDate);
                        qm.getPersistenceManager().makePersistent(attribution);
                    } else {
                        logger.debug("%s: Encountered dangling attribution; Re-using by updating firstSeen and lastSeen timestamps".formatted(persistentVuln.getVulnId()));
                        final AffectedVersionAttribution existingAttribution = qm.getAffectedVersionAttribution(persistentVuln, existingVs, Vulnerability.Source.NVD);
                        existingAttribution.setFirstSeen(attributionDate);
                        existingAttribution.setLastSeen(attributionDate);
                    }
                    vsListToKeep.add(existingVs);
                } else {
                    logger.trace("%s: Creating new VS".formatted(persistentVuln.getVulnId()));
                    final VulnerableSoftware persistentVs = qm.getPersistenceManager().makePersistent(vs);
                    final AffectedVersionAttribution attribution = createAttribution(persistentVuln, persistentVs, attributionDate);
                    qm.getPersistenceManager().makePersistent(attribution);
                    vsListToKeep.add(persistentVs);
                }
            }

            logger.trace("%s: Final vsList: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            if (!Objects.equals(persistentVuln.getVulnerableSoftware(), vsListToKeep)) {
                logger.trace("%s: vsList has changed: %s".formatted(persistentVuln.getVulnId(), new PersistenceUtil.Diff(persistentVuln.getVulnerableSoftware(), vsListToKeep)));
                persistentVuln.setVulnerableSoftware(vsListToKeep);
            }
        });
    }

    private static AffectedVersionAttribution createAttribution(final Vulnerability vuln, final VulnerableSoftware vs,
                                                                final Date attributionDate) {
        final var attribution = new AffectedVersionAttribution();
        attribution.setSource(Vulnerability.Source.NVD);
        attribution.setVulnerability(vuln);
        attribution.setVulnerableSoftware(vs);
        attribution.setFirstSeen(attributionDate);
        attribution.setLastSeen(attributionDate);
        return attribution;
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
