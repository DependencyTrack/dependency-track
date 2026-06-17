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

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.License;
import org.dependencytrack.model.PolicyCondition;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;
import java.util.Map;

final class LicenseQueryManager extends QueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    LicenseQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    LicenseQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a List of all License objects.
     * @return a List of all License objects
     */
    public PaginatedResult getLicenses() {
        final Query<License> query = pm.newQuery(License.class);
        query.getFetchPlan().addGroup(License.FetchGroup.ALL.name());
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter) || licenseId.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a concise List of all Licenses.
     * This method if designed NOT to provide paginated results.
     * @return a List of License objects
     */
    @SuppressWarnings("unchecked")
    public List<License> getAllLicensesConcise() {
        final Query<License> query = pm.newQuery(License.class);
        query.getFetchPlan().addGroup(License.FetchGroup.CONCISE.name());
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return (List<License>)query.execute();
    }

    /**
     * Returns a License object from the specified SPDX license ID.
     * @param licenseId the SPDX license ID to retrieve
     * @return a License object, or null if not found
     */
    public License getLicense(String licenseId) {
        final Query<License> query = pm.newQuery(License.class, "licenseId == :licenseId");
        query.getFetchPlan().addGroup(License.FetchGroup.ALL.name());
        query.setRange(0, 1);
        return singleResult(query.execute(licenseId));
    }

    /**
     * @since 4.12.0
     */
    @Override
    public License getLicenseByIdOrName(final String licenseIdOrName) {
        final Query<License> query = pm.newQuery(License.class);
        query.setFilter("licenseId == :licenseIdOrName || name == :licenseIdOrName");
        query.setNamedParameters(Map.of("licenseIdOrName", licenseIdOrName));
        query.setOrdering("licenseId asc"); // Ensure result is consistent.
        query.setRange(0, 1); // Multiple licenses can have the same name; Pick the first one.
        final License license = query.executeUnique();
        return license != null ? license : License.UNRESOLVED;
    }

    /**
     * Creates a new custom license.
     * @param license the license to create
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created license
     */
    public License createCustomLicense(License license, boolean commitIndex) {
        license.setCustomLicense(true);
        final License result = persist(license);
        return result;
    }

    /**
     * @since 4.12.0
     */
    @Override
    public License getCustomLicenseByName(final String licenseName) {
        final Query<License> query = pm.newQuery(License.class);
        query.setFilter("name == :name && customLicense == true");
        query.setParameters(licenseName);
        query.setOrdering("licenseId asc"); // Ensure result is consistent.
        query.setRange(0, 1); // Multiple licenses can have the same name; Pick the first one.
        final License license = query.executeUnique();
        return license != null ? license : License.UNRESOLVED;
    }

    /**
     * Deletes a license.
     * @param license the license to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void deleteLicense(final License license, final boolean commitIndex) {
        final Query<PolicyCondition> query = pm.newQuery(PolicyCondition.class, "subject == :subject && value == :value");
        List<PolicyCondition> policyConditions = (List<PolicyCondition>)query.execute(PolicyCondition.Subject.LICENSE ,license.getUuid().toString());
        delete(license);
        delete(policyConditions);
    }
}
