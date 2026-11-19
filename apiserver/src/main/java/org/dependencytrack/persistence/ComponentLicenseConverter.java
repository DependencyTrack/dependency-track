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

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.License;
import org.dependencytrack.api.v2.model.UpdateComponentLicenseRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.jdbi.ComponentDao;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;

public class ComponentLicenseConverter {

    public static List<ComponentDao.ComponentLicenseRow> buildComponentLicenseRows(
            final Component component, final long persistedId, final Map<String, Long> licenseIds) {

        // LinkedHashMap lends itself to keeping the ordinality intact
        final Map<String, ComponentDao.ComponentLicenseRow> rowMap = new LinkedHashMap<>();
        final List<License> candidates = component.getLicenseCandidates();
        final String expression = trimToNull(component.getLicenseExpression());

        if (candidates != null) {
            for (final License candidate : candidates) {
                String trimmedName = trimToNull(candidate.getName());
                String trimmedId = trimToNull(candidate.getId());

                final String identifier = isNotBlank(trimmedId) ? trimmedId : trimmedName;
                if (isBlank(identifier)) {
                    continue;
                }

                final Long licenseId = licenseIds.get(identifier);

                final boolean isExpression = expression != null
                        && (expression.equals(candidate.getId()) || expression.equals(candidate.getName()));

                // De-deuplicate licenseIDs to satisfy COMPONENTLICENSES_ID_IDX constraint
                String key = licenseId != null ? "resolved:" + licenseId : "unresolved:" + identifier;
                rowMap.putIfAbsent(
                        key,
                        new ComponentDao.ComponentLicenseRow(
                                null,
                                persistedId,
                                licenseId,
                                licenseId == null
                                        ? trimmedName != null ? trimmedName : trimToNull(candidate.getId())
                                        : null,
                                isExpression ? expression : null,
                                trimToNull(candidate.getUrl()),
                                0,
                                "DECLARED"));
            }
        }

        // Per the CycloneDX protos, expressions are sufficient substitutes for a license model object,
        // thus stored separately and requiring separate retrieval
        if (expression != null
                && (candidates == null
                        || candidates.stream()
                                .noneMatch(candidate -> expression.equals(candidate.getId())
                                        || expression.equals(candidate.getName())))) {
            rowMap.putIfAbsent(
                    "expression",
                    new ComponentDao.ComponentLicenseRow(0L, persistedId, null, null, expression, null, 0, "DECLARED"));
        }

        // Assign ordinalities now that rows are de-duplicated
        final List<ComponentDao.ComponentLicenseRow> finalRows = new ArrayList<>(rowMap.size());
        int ordinality = 1;
        for (ComponentDao.ComponentLicenseRow currentRow : rowMap.values()) {
            finalRows.add(new ComponentDao.ComponentLicenseRow(
                    currentRow.id(),
                    currentRow.componentId(),
                    currentRow.licenseId(),
                    currentRow.license(),
                    currentRow.licenseExpression(),
                    currentRow.licenseUrl(),
                    ordinality++,
                    currentRow.acknowledgement()));
        }

        return finalRows;
    }

    public static List<ComponentDao.ComponentLicenseRow> buildComponentLicenseRows(
            final long componentId,
            final List<UpdateComponentLicenseRequest> licenseRequests,
            final Map<String, Long> licenseIdsByIdentifier) {
        if (licenseRequests == null || licenseRequests.isEmpty()) {
            return List.of();
        }

        final Map<String, ComponentDao.ComponentLicenseRow> rowsByKey = new LinkedHashMap<>();

        for (final UpdateComponentLicenseRequest request : licenseRequests) {
            final String license = StringUtils.trimToNull(request.getLicense());
            final String expression = StringUtils.trimToNull(request.getLicenseExpression());

            final String key;
            if (expression != null) {
                key = "expression:" + expression;
            } else if (license != null) {
                key = "license:" + license;
            } else {
                continue;
            }

            Long licenseId = license != null ? licenseIdsByIdentifier.get(license) : null;

            rowsByKey.putIfAbsent(
                    key,
                    new ComponentDao.ComponentLicenseRow(
                            null,
                            componentId,
                            licenseId,
                            licenseId == null ? license : null,
                            expression,
                            StringUtils.trimToNull(request.getLicenseUrl()),
                            0,
                            request.getAcknowledgement().name()));
        }

        final List<ComponentDao.ComponentLicenseRow> licenseRows = new ArrayList<>(rowsByKey.size());

        int ordinality = 1;
        for (final ComponentDao.ComponentLicenseRow row : rowsByKey.values()) {
            licenseRows.add(new ComponentDao.ComponentLicenseRow(
                    row.id(),
                    row.componentId(),
                    row.licenseId(),
                    row.license(),
                    row.licenseExpression(),
                    row.licenseUrl(),
                    ordinality++,
                    row.acknowledgement()));
        }

        return licenseRows;
    }
}
