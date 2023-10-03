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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.persistence;

import alpine.event.framework.Event;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.h2.util.StringUtils;
import us.springett.parsers.cpe.values.LogicalValue;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

final class VulnerableSoftwareQueryManager extends QueryManager implements IQueryManager {

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
     * Synchronize a Cpe, updating it if it needs updating, or creating it if it doesn't exist.
     * @param cpe the Cpe object to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a synchronize Cpe object
     */
    public Cpe synchronizeCpe(Cpe cpe, boolean commitIndex) {
        Cpe result = getCpeBy23(cpe.getCpe23());
        if (result == null) {
            result = persist(cpe);
            Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, Cpe.class);
        }
        return result;
    }

    /**
     * Returns a CPE by it's CPE v2.3 string.
     * @param cpe23 the CPE 2.3 string
     * @return a CPE object, or null if not found
     */
    public Cpe getCpeBy23(String cpe23) {
        final Query<Cpe> query = pm.newQuery(Cpe.class, "cpe23 == :cpe23");
        query.setRange(0, 1);
        return singleResult(query.execute(cpe23));
    }

    /**
     * Returns a List of all CPE objects.
     * @return a List of all CPE objects
     */
    public PaginatedResult getCpes() {
        final Query<Cpe> query = pm.newQuery(Cpe.class);
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
     * Returns a List of all CPE objects that match the specified CPE (v2.2 or v2.3) uri.
     * @return a List of matching CPE objects
     */
    @SuppressWarnings("unchecked")
    public List<Cpe> getCpes(final String cpeString) {
        final Query<Cpe> query = pm.newQuery(Cpe.class, "cpe23 == :cpeString || cpe22 == :cpeString");
        return (List<Cpe>)query.execute(cpeString);
    }

    /**
     * Returns a List of all CPE objects that match the specified vendor/product/version.
     * @return a List of matching CPE objects
     */
    @SuppressWarnings("unchecked")
    public List<Cpe> getCpes(final String part, final String vendor, final String product, final String version) {
        final Query<Cpe> query = pm.newQuery(Cpe.class);
        query.setFilter("part == :part && vendor == :vendor && product == :product && version == :version");
        return (List<Cpe>)query.executeWithArray(part, vendor, product, version);
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
        return query.executeUnique();
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
     * Returns a List of all VulnerableSoftware objects that match the specified PackageURL
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public VulnerableSoftware getVulnerableSoftwareByPurl(String purlType, String purlNamespace, String purlName,
                                                                   String versionEndExcluding, String versionEndIncluding,
                                                                   String versionStartExcluding, String versionStartIncluding) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && versionEndExcluding == :versionEndExcluding && versionEndIncluding == :versionEndIncluding && versionStartExcluding == :versionStartExcluding && versionStartIncluding == :versionStartIncluding");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(purlType, purlNamespace, purlName, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding));
    }

    /**
     * Fetch all {@link VulnerableSoftware} instances associated with a given {@link Vulnerability}.
     *
     * @param source The source of the vulnerability
     * @param vulnId The ID of the vulnerability
     * @return a {@link List} of {@link VulnerableSoftware}s
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getVulnerableSoftwareByVulnId(final String source, final String vulnId) {
        final Query<?> query = pm.newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.VulnerableSoftware
                WHERE vulnerabilities.contains(vuln)
                    && vuln.source == :source && vuln.vulnId == :vulnId
                VARIABLES org.dependencytrack.model.Vulnerability vuln
                """);
        query.setParameters(source, vulnId);
        return (List<VulnerableSoftware>) query.executeList();
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

            if (!LogicalValue.ANY.getAbbreviation().equals(cpePart)
                    && !LogicalValue.NA.getAbbreviation().equals(cpePart)) {
                // | No. | Source A-V      | Target A-V | Relation             |
                // | :-- | :-------------- | :--------- | :------------------- |
                // | 3   | ANY             | i          | SUPERSET             |
                // | 7   | NA              | i          | DISJOINT             |
                // | 9   | i               | i          | EQUAL                |
                // | 10  | i               | k          | DISJOINT             |
                // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
                cpeQueryFilterParts.add("(part == '*' || part.equalsIgnoreCase(:part))");
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
            } else if (LogicalValue.NA.getAbbreviation().equals(cpePart)) {
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
                // | 13  | i              | ANY        | SUPERSET |
                // | 15  | m + wild cards | ANY        | SUPERSET |
                cpeQueryFilterParts.add("part != null");
            }

            if (!LogicalValue.ANY.getAbbreviation().equals(cpeVendor)
                    && !LogicalValue.NA.getAbbreviation().equals(cpeVendor)) {
                cpeQueryFilterParts.add("(vendor == '*' || vendor.equalsIgnoreCase(:vendor))");
                queryParams.put("vendor", cpeVendor);
            } else if (LogicalValue.NA.getAbbreviation().equals(cpeVendor)) {
                cpeQueryFilterParts.add("(vendor == '*' || vendor == '-')");
            } else {
                cpeQueryFilterParts.add("vendor != null");
            }

            if (!LogicalValue.ANY.getAbbreviation().equals(cpeProduct)
                    && !LogicalValue.NA.getAbbreviation().equals(cpeProduct)) {
                cpeQueryFilterParts.add("(product == '*' || product.equalsIgnoreCase(:product))");
                queryParams.put("product", cpeProduct);
            } else if (LogicalValue.NA.getAbbreviation().equals(cpeProduct)) {
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
     * Checks if the specified CWE id exists or not. If not, creates
     * a new CWE with the specified ID and name. In both cases, the
     * CWE will be returned.
     * @param id the CWE ID
     * @param name the name of the CWE
     * @return a CWE object
     */
    public Cwe createCweIfNotExist(int id, String name) {
        Cwe cwe = getCweById(id);
        if (cwe != null) {
            return cwe;
        }
        cwe = new Cwe();
        cwe.setCweId(id);
        cwe.setName(name);
        return persist(cwe);
    }

    /**
     * Returns a CWE by it's CWE-ID.
     * @param cweId the CWE-ID
     * @return a CWE object, or null if not found
     */
    public Cwe getCweById(int cweId) {
        final Query<Cwe> query = pm.newQuery(Cwe.class, "cweId == :cweId");
        query.setRange(0, 1);
        return singleResult(query.execute(cweId));
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    public PaginatedResult getCwes() {
        final Query<Cwe> query = pm.newQuery(Cwe.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            if (StringUtils.isNumber(filter)) {
                query.setFilter("cweId == :cweId || name.matches(:filter)");
                final String filterString = ".*" + filter.toLowerCase() + ".*";
                return execute(query, Integer.valueOf(filter), filterString);
            } else {
                query.setFilter("name.toLowerCase().matches(:filter)");
                final String filterString = ".*" + filter.toLowerCase() + ".*";
                return execute(query, filterString);
            }
        }
        return execute(query);
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    public List<Cwe> getAllCwes() {
        final Query<Cwe> query = pm.newQuery(Cwe.class);
        query.setOrdering("id asc");
        return query.executeList();
    }
}
