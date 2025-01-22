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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.stream.Collectors.groupingBy;
import static org.dependencytrack.util.PersistenceUtil.assertNonPersistentAll;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

final class VulnerableSoftwareQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(VulnerableSoftwareQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    VulnerableSoftwareQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    VulnerableSoftwareQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a VulnerableSoftware by it's CPE v2.3 string.
     * @param cpe23 the CPE 2.3 string
     * @return a VulnerableSoftware object, or null if not found
     */
    public VulnerableSoftware getVulnerableSoftwareByCpe23(String cpe23,
                                                           String versionEndExcluding, String versionEndIncluding,
                                                           String versionStartExcluding, String versionStartIncluding) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        var filter = "cpe23 == :cpe23";
        final var parameters = new HashMap<String, Object>();
        parameters.put("cpe23", Objects.requireNonNull(cpe23));

        // When building the query filter, ensure that null values are
        // not passed as parameters, as this would bypass the query compilation
        // cache. This method is called very frequently during NVD mirroring,
        // we should avoid the overhead of repeated re-compilation if possible.
        // See also: https://github.com/DependencyTrack/dependency-track/issues/2540
        if (versionEndExcluding != null) {
            filter += " && versionEndExcluding == :vee";
            parameters.put("vee", versionEndExcluding);
        } else {
            filter += " && versionEndExcluding == null";
        }
        if (versionEndIncluding != null) {
            filter += " && versionEndIncluding == :vei";
            parameters.put("vei", versionEndIncluding);
        } else {
            filter += " && versionEndIncluding == null";
        }
        if (versionStartExcluding != null) {
            filter += " && versionStartExcluding == :vse";
            parameters.put("vse", versionStartExcluding);
        } else {
            filter += " && versionStartExcluding == null";
        }
        if (versionStartIncluding != null) {
            filter += " && versionStartIncluding == :vsi";
            parameters.put("vsi", versionStartIncluding);
        } else {
            filter += " && versionStartIncluding == null";
        }
        query.setFilter(filter);
        query.setNamedParameters(parameters);
        query.setRange(0, 1);
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    /**
     * Returns a List of all VulnerableSoftware objects.
     * @return a List of all VulnerableSoftware objects
     */
    public PaginatedResult getVulnerableSoftware() {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vendor.toLowerCase().matches(:filter) || product.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified CPE (v2.2 or v2.3) uri.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftwareByCpe(final String cpeString) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "cpe23 == :cpeString || cpe22 == :cpeString");
        return (List<VulnerableSoftware>)query.execute(cpeString);
    }

    /**
     * @since 4.12.3
     */
    public VulnerableSoftware getVulnerableSoftwareByPurl(
            final String purlType,
            final String purlNamespace,
            final String purlName,
            final String version,
            final String versionEndExcluding,
            final String versionEndIncluding,
            final String versionStartExcluding,
            final String versionStartIncluding) {
        final var queryFilterParts = new ArrayList<>(List.of(
                "purlType == :purlType",
                "purlName == :purlName"));
        final var queryParams = new HashMap<String, Object>(Map.ofEntries(
                Map.entry("purlType", purlType),
                Map.entry("purlName", purlName)));

        if (purlNamespace == null) {
            queryFilterParts.add("purlNamespace == null");
        } else {
            queryFilterParts.add("purlNamespace == :purlNamespace");
            queryParams.put("purlNamespace", purlNamespace);
        }

        if (version != null) {
            queryFilterParts.add("version == :version");
            queryParams.put("version", version);
        } else {
            queryFilterParts.add("version == null");
        }

        if (versionEndExcluding == null) {
            queryFilterParts.add("versionEndExcluding == null");
        } else {
            queryFilterParts.add("versionEndExcluding == :versionEndExcluding");
            queryParams.put("versionEndExcluding", versionEndExcluding);
        }

        if (versionEndIncluding == null) {
            queryFilterParts.add("versionEndIncluding == null");
        } else {
            queryFilterParts.add("versionEndIncluding == :versionEndIncluding");
            queryParams.put("versionEndIncluding", versionEndIncluding);
        }

        if (versionStartExcluding == null) {
            queryFilterParts.add("versionStartExcluding == null");
        } else {
            queryFilterParts.add("versionStartExcluding == :versionStartExcluding");
            queryParams.put("versionStartExcluding", versionStartExcluding);
        }

        if (versionStartIncluding == null) {
            queryFilterParts.add("versionStartIncluding == null");
        } else {
            queryFilterParts.add("versionStartIncluding == :versionStartIncluding");
            queryParams.put("versionStartIncluding", versionStartIncluding);
        }

        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter(String.join(" && ", queryFilterParts));
        query.setNamedParameters(queryParams);
        query.setRange(0, 1);
        return executeAndCloseUnique(query);
    }

    /**
     * Fetch all {@link VulnerableSoftware} instances associated with a given {@link Vulnerability}.
     *
     * @param source The source of the vulnerability
     * @param vulnId The ID of the vulnerability
     * @return a {@link List} of {@link VulnerableSoftware}s
     */
    @Override
    public List<VulnerableSoftware> getVulnerableSoftwareByVulnId(final String source, final String vulnId) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("vulnerabilities.contains(vuln) && vuln.source == :source && vuln.vulnId == :vulnId");
        query.declareVariables("org.dependencytrack.model.Vulnerability vuln");
        query.setNamedParameters(Map.of(
                "source", source,
                "vulnId", vulnId
        ));
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified PackageURL
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftwareByPurl(final PackageURL purl) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "(purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && purlVersion == :purlVersion)");
        return (List<VulnerableSoftware>)query.executeWithArray(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion());
    }

    /**
     * Fetch all {@link VulnerableSoftware}s matching the given CPE part, vendor, product, or Package URL.
     * <p>
     * This method will not query for <em>exact</em> matches of the given CPE attributes,
     * but instead follow the CPE name matching specification.
     *
     * @param cpePart    The part attribute of the target CPE
     * @param cpeVendor  The vendor attribute of the target CPE
     * @param cpeProduct The product attribute of the target CPE
     * @param purl       The Package URL
     * @return A {@link List} of all matching {@link VulnerableSoftware}s
     */
    public List<VulnerableSoftware> getAllVulnerableSoftware(final String cpePart, final String cpeVendor,
                                                             final String cpeProduct, final PackageURL purl) {
        var queryFilterParts = new ArrayList<String>();
        var queryParams = new HashMap<String, Object>();

        if (cpePart != null && cpeVendor != null && cpeProduct != null) {
            final var cpeQueryFilterParts = new ArrayList<String>();

            // The query composition below represents a partial implementation of the CPE
            // matching logic. It makes references to table 6-2 of the CPE name matching
            // specification: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
            //
            // In CPE matching terms, the parameters of this method represent the target,
            // and the `VulnerableSoftware`s in the database represent the source.
            //
            // While the source *can* contain wildcards ("*", "?"), there is currently (Oct. 2023)
            // no occurrence of part, vendor, or product with wildcards in the NVD database.
            // Evaluating wildcards in the source can only be done in-memory. If we wanted to do that,
            // we'd have to fetch *all* records, which is not practical.

            if (!"*".equals(cpePart) && !"-".equals(cpePart)) {
                // | No. | Source A-V      | Target A-V | Relation             |
                // | :-- | :-------------- | :--------- | :------------------- |
                // | 3   | ANY             | i          | SUPERSET             |
                // | 7   | NA              | i          | DISJOINT             |
                // | 9   | i               | i          | EQUAL                |
                // | 10  | i               | k          | DISJOINT             |
                // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
                // TODO: Filter should use equalsIgnoreCase as CPE matching is case-insensitive.
                //   Can't currently do this as it would require an index on UPPER("PART"),
                //   which we cannot add through JDO annotations.
                cpeQueryFilterParts.add("(part == '*' || part == :part)");
                queryParams.put("part", cpePart);

                // NOTE: Target *could* include wildcard, but the relation
                // for those cases is undefined:
                //
                // | No. | Source A-V      | Target A-V      | Relation   |
                // | :-- | :-------------- | :-------------- | :--------- |
                // | 4   | ANY             | m + wild cards  | undefined  |
                // | 8   | NA              | m + wild cards  | undefined  |
                // | 11  | i               | m + wild cards  | undefined  |
                // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
            } else if ("-".equals(cpePart)) {
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 2   | ANY            | NA         | SUPERSET |
                // | 6   | NA             | NA         | EQUAL    |
                // | 12  | i              | NA         | DISJOINT |
                // | 16  | m + wild cards | NA         | DISJOINT |
                cpeQueryFilterParts.add("(part == '*' || part == '-')");
            } else {
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 1   | ANY            | ANY        | EQUAL    |
                // | 5   | NA             | ANY        | SUBSET   |
                // | 13  | i              | ANY        | SUBSET   |
                // | 15  | m + wild cards | ANY        | SUBSET   |
                cpeQueryFilterParts.add("part != null");
            }

            if (!"*".equals(cpeVendor) && !"-".equals(cpeVendor)) {
                // TODO: Filter should use equalsIgnoreCase as CPE matching is case-insensitive.
                //   Can't currently do this as it would require an index on UPPER("VENDOR"),
                //   which we cannot add through JDO annotations.
                cpeQueryFilterParts.add("(vendor == '*' || vendor == :vendor)");
                queryParams.put("vendor", cpeVendor);
            } else if ("-".equals(cpeVendor)) {
                cpeQueryFilterParts.add("(vendor == '*' || vendor == '-')");
            } else {
                cpeQueryFilterParts.add("vendor != null");
            }

            if (!"*".equals(cpeProduct) && !"-".equals(cpeProduct)) {
                // TODO: Filter should use equalsIgnoreCase as CPE matching is case-insensitive.
                //   Can't currently do this as it would require an index on UPPER("PRODUCT"),
                //   which we cannot add through JDO annotations.
                cpeQueryFilterParts.add("(product == '*' || product == :product)");
                queryParams.put("product", cpeProduct);
            } else if ("-".equals(cpeProduct)) {
                cpeQueryFilterParts.add("(product == '*' || product == '-')");
            } else {
                cpeQueryFilterParts.add("product != null");
            }

            queryFilterParts.add("(%s)".formatted(String.join(" && ", cpeQueryFilterParts)));
        }

        if (purl != null) {
            final var purlFilterParts = new ArrayList<String>();

            // Use explicit null matching to avoid bypassing of the query compilation cache.
            // https://github.com/DependencyTrack/dependency-track/issues/2540

            if (purl.getType() != null) {
                purlFilterParts.add("purlType == :purlType");
                queryParams.put("purlType", purl.getType());
            } else {
                purlFilterParts.add("purlType == null");
            }

            if (purl.getNamespace() != null) {
                purlFilterParts.add("purlNamespace == :purlNamespace");
                queryParams.put("purlNamespace", purl.getNamespace());
            } else {
                purlFilterParts.add("purlNamespace == null");
            }

            if (purl.getName() != null) {
                purlFilterParts.add("purlName == :purlName");
                queryParams.put("purlName", purl.getName());
            } else {
                purlFilterParts.add("purlName == null");
            }

            queryFilterParts.add("(%s)".formatted(String.join(" && ", purlFilterParts)));
        }

        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter(String.join(" || ", queryFilterParts));
        query.setNamedParameters(queryParams);
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    /**
     * @since 4.12.0
     */
    public void synchronizeVulnerableSoftware(
            final Vulnerability persistentVuln,
            final List<VulnerableSoftware> vsList,
            final Vulnerability.Source source) {
        assertPersistent(persistentVuln, "vuln must be persistent");
        assertNonPersistentAll(vsList, "vsList must not be persistent");

        runInTransaction(() -> {
            // Get all VulnerableSoftware records that are currently associated with the vulnerability.
            // Note: For SOME ODD REASON, duplicate (as in, same database ID and all) VulnerableSoftware
            // records are returned, when operating on data that was originally created by the feed-based
            // NistMirrorTask. We thus have to deduplicate here.
            final List<VulnerableSoftware> vsOldList = persistentVuln.getVulnerableSoftware().stream().distinct().toList();
            LOGGER.trace("%s: Existing VS: %d".formatted(persistentVuln.getVulnId(), vsOldList.size()));

            // Get attributions for all existing VulnerableSoftware records.
            final Map<Long, List<AffectedVersionAttribution>> attributionsByVsId =
                    getAffectedVersionAttributions(persistentVuln, vsOldList).stream()
                            .collect(groupingBy(attribution -> attribution.getVulnerableSoftware().getId()));
            for (final VulnerableSoftware vsOld : vsOldList) {
                vsOld.setAffectedVersionAttributions(attributionsByVsId.get(vsOld.getId()));
            }

            // Based on the lists of currently reported, and previously reported VulnerableSoftware records,
            // divide the previously reported ones into lists of records to keep, and records to remove.
            // Records to keep are removed from vsList. Remaining records in vsList thus are entirely new.
            final var vsListToRemove = new ArrayList<VulnerableSoftware>();
            final var vsListToKeep = new ArrayList<VulnerableSoftware>();

            // Separately track existing VulnerableSoftware records that are reported by the source.
            // Records in this list must be attributed to the source.
            // Records in vsListToKeep that are NOT in this list could have been reported by other sources.
            final var matchedOldVsList = new ArrayList<VulnerableSoftware>();

            for (final VulnerableSoftware vsOld : vsOldList) {
                if (vsList.removeIf(vsOld::equalsIgnoringDatastoreIdentity)) {
                    vsListToKeep.add(vsOld);
                    matchedOldVsList.add(vsOld);
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

                    final boolean previouslyReportedBySource = attributions.stream()
                            .anyMatch(attr -> attr.getSource() == source);
                    final boolean previouslyReportedByOthers = !previouslyReportedBySource;

                    if (previouslyReportedByOthers) {
                        vsListToKeep.add(vsOld);
                    } else {
                        vsListToRemove.add(vsOld);
                    }
                }
            }
            LOGGER.trace("%s: vsListToKeep: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            LOGGER.trace("%s: vsListToRemove: %d".formatted(persistentVuln.getVulnId(), vsListToRemove.size()));

            // Remove attributions for VulnerableSoftware records that are no longer reported.
            if (!vsListToRemove.isEmpty()) {
                deleteAffectedVersionAttributions(persistentVuln, vsListToRemove, source);
            }

            final var attributionDate = new Date();

            // For VulnerableSoftware records that existed before, update the lastSeen timestamp,
            // or create an attribution if it doesn't exist already.
            for (final VulnerableSoftware oldVs : vsListToKeep) {
                boolean hasAttribution = false;
                for (final AffectedVersionAttribution attribution : oldVs.getAffectedVersionAttributions()) {
                    if (attribution.getSource() == source) {
                        attribution.setLastSeen(attributionDate);
                        hasAttribution = true;
                        break;
                    }
                }

                // The record was previously reported by others, but now the source reports it, too.
                // Ensure that an attribution is added accordingly.
                if (matchedOldVsList.contains(oldVs) && !hasAttribution) {
                    LOGGER.trace("%s: Adding attribution".formatted(persistentVuln.getVulnId()));
                    final AffectedVersionAttribution attribution = createAttribution(
                            persistentVuln, oldVs, attributionDate, source);
                    persist(attribution);
                }
            }

            // For VulnerableSoftware records that are newly reported for this vulnerability, check if any matching
            // records exist in the database that are currently associated with other (or no) vulnerabilities.
            for (final VulnerableSoftware vs : vsList) {
                final VulnerableSoftware existingVs;
                if (vs.getCpe23() != null) {
                    existingVs = getVulnerableSoftwareByCpe23(
                            vs.getCpe23(),
                            vs.getVersionEndExcluding(),
                            vs.getVersionEndIncluding(),
                            vs.getVersionStartExcluding(),
                            vs.getVersionStartIncluding());
                } else if (vs.getPurl() != null) {
                    existingVs = getVulnerableSoftwareByPurl(
                            vs.getPurlType(),
                            vs.getPurlNamespace(),
                            vs.getPurlName(),
                            vs.getVersion(),
                            vs.getVersionEndExcluding(),
                            vs.getVersionEndIncluding(),
                            vs.getVersionStartExcluding(),
                            vs.getVersionStartIncluding());
                } else {
                    throw new IllegalStateException("VulnerableSoftware must define a CPE or PURL, but %s has neither".formatted(vs));
                }
                if (existingVs != null) {
                    final boolean hasAttribution = hasAffectedVersionAttribution(persistentVuln, existingVs, source);
                    if (!hasAttribution) {
                        LOGGER.trace("%s: Adding attribution".formatted(persistentVuln.getVulnId()));
                        final AffectedVersionAttribution attribution = createAttribution(persistentVuln, existingVs, attributionDate, source);
                        persist(attribution);
                    } else {
                        LOGGER.debug("%s: Encountered dangling attribution; Re-using by updating firstSeen and lastSeen timestamps".formatted(persistentVuln.getVulnId()));
                        final AffectedVersionAttribution existingAttribution = getAffectedVersionAttribution(persistentVuln, existingVs, source);
                        existingAttribution.setFirstSeen(attributionDate);
                        existingAttribution.setLastSeen(attributionDate);
                    }
                    vsListToKeep.add(existingVs);
                } else {
                    LOGGER.trace("%s: Creating new VS".formatted(persistentVuln.getVulnId()));
                    final VulnerableSoftware persistentVs = persist(vs);
                    final AffectedVersionAttribution attribution = createAttribution(persistentVuln, persistentVs, attributionDate, source);
                    persist(attribution);
                    vsListToKeep.add(persistentVs);
                }
            }

            LOGGER.trace("%s: Final vsList: %d".formatted(persistentVuln.getVulnId(), vsListToKeep.size()));
            if (!Objects.equals(persistentVuln.getVulnerableSoftware(), vsListToKeep)) {
                LOGGER.trace("%s: vsList has changed: %s".formatted(persistentVuln.getVulnId(), new PersistenceUtil.Diff(persistentVuln.getVulnerableSoftware(), vsListToKeep)));
                persistentVuln.setVulnerableSoftware(vsListToKeep);
            }
        });
    }

    private static AffectedVersionAttribution createAttribution(
            final Vulnerability vuln,
            final VulnerableSoftware vs,
            final Date attributionDate,
            final Vulnerability.Source source) {
        final var attribution = new AffectedVersionAttribution();
        attribution.setSource(source);
        attribution.setVulnerability(vuln);
        attribution.setVulnerableSoftware(vs);
        attribution.setFirstSeen(attributionDate);
        attribution.setLastSeen(attributionDate);
        return attribution;
    }

}
