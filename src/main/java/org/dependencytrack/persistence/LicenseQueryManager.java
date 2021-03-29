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
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.License;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;

final class LicenseQueryManager extends QueryManager implements IQueryManager {

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
        return singleResult(query.execute(licenseId));
    }

    /**
     * Creates a new License.
     * @param license the License object to create
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a created License object
     */
    private License createLicense(License license, boolean commitIndex) {
        final License result = persist(license);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, License.class);
        return result;
    }

    /**
     * Updates a license.
     * @param transientLicense the license to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a License object
     */
    private License updateLicense(License transientLicense, boolean commitIndex) {
        final License license;
        if (transientLicense.getId() > 0) {
            license = getObjectById(License.class, transientLicense.getId());
        } else {
            license = getLicense(transientLicense.getLicenseId());
        }

        if (license != null) {
            license.setLicenseId(transientLicense.getLicenseId());
            license.setName(transientLicense.getName());
            license.setText(transientLicense.getText());
            license.setHeader(transientLicense.getHeader());
            license.setTemplate(transientLicense.getTemplate());
            license.setOsiApproved(transientLicense.isOsiApproved());
            license.setFsfLibre(transientLicense.isFsfLibre());
            license.setDeprecatedLicenseId(transientLicense.isDeprecatedLicenseId());
            license.setComment(transientLicense.getComment());
            license.setSeeAlso(transientLicense.getSeeAlso());

            final License result = persist(license);
            Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, License.class);
            return result;
        }
        return null;
    }

    /**
     * Synchronize a License, updating it if it needs updating, or creating it if it doesn't exist.
     * @param license the License object to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a synchronize License object
     */
    License synchronizeLicense(License license, boolean commitIndex) {
        License result = updateLicense(license, commitIndex);
        if (result == null) {
            result = createLicense(license, commitIndex);
        }
        return result;
    }
}
