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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.LicensesApi;
import org.dependencytrack.api.v2.model.ListLicensesResponse;
import org.dependencytrack.api.v2.model.ListLicensesResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.query.ListComponentLicensesQuery;
import org.dependencytrack.resources.AbstractApiResource;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;

@Provider
public class LicensesResource extends AbstractApiResource implements LicensesApi {

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponentLicenses(UUID uuid, Integer limit, String pageToken) {

        return withJdbiHandle(getAlpineRequest(), handle -> {
            ComponentDao componentDao = handle.attach(ComponentDao.class);
            final Long componentId = componentDao.getComponentId(uuid);
            requireComponentAccess(handle, uuid);

            final Page<ComponentDao.ComponentLicenseRow> licensesPage = componentDao.getPaginatedComponentLicenseRows(
                    new ListComponentLicensesQuery(componentId, limit, pageToken));

            final ArrayList<ListLicensesResponseItem> responseItems =
                    new ArrayList<ListLicensesResponseItem>(licensesPage.items().size());

            final Map<Long, License> licensesById = loadLicenses(componentDao, licensesPage.items());

            for (final ComponentDao.ComponentLicenseRow licenseRow : licensesPage.items()) {
                final License resolvedLicense =
                        licenseRow.licenseId() != null ? licensesById.get(licenseRow.licenseId()) : null;
                final ListLicensesResponseItem item = ListLicensesResponseItem.builder()
                        .resolvedLicense(mapLicense(resolvedLicense))
                        .license(licenseRow.license())
                        .licenseExpression(licenseRow.licenseExpression())
                        .licenseUrl(licenseRow.licenseUrl() != null ? URI.create(licenseRow.licenseUrl()) : null)
                        .ordinality(licenseRow.ordinality())
                        .acknowledgement(licenseRow.acknowledgement())
                        .build();
                responseItems.add(item);
            }

            final var response = ListLicensesResponse.builder()
                    .items(responseItems)
                    .nextPageToken(licensesPage.nextPageToken())
                    .total(convertTotalCount(licensesPage.totalCount()))
                    .build();
            return Response.ok(response).build();
        });
    }

    private Map<Long, License> loadLicenses(
            final ComponentDao componentDao, final Collection<ComponentDao.ComponentLicenseRow> licenseRows) {
        final Set<Long> licenseIds = licenseRows.stream()
                .map(ComponentDao.ComponentLicenseRow::licenseId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        Map<Long, ComponentDao.LicenseRow> licenseRowMap = componentDao.getLicenseRowsByIds(licenseIds);
        HashMap<Long, License> licenseMap = new HashMap<Long, License>();
        for (Long current : licenseRowMap.keySet()) {
            ComponentDao.LicenseRow licenseRow = licenseRowMap.get(current);
            License newLicense = new License();
            newLicense.setName(licenseRow.name());
            newLicense.setCustomLicense(licenseRow.customLicense());
            newLicense.setFsfLibre(licenseRow.fsfLibre());
            newLicense.setLicenseId(licenseRow.licenseId());
            newLicense.setOsiApproved(licenseRow.osiApproved());
            newLicense.setUuid(licenseRow.uuid());
            licenseMap.put(current, newLicense);
        }

        return licenseMap;
    }
}
