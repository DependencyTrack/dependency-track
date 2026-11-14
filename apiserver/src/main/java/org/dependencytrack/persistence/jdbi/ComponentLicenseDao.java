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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.dependencytrack.support.jdbi.binding.Bindings.columnValues;

/// @since 5.3.0
@NullMarked
public interface ComponentLicenseDao extends SqlObject {

    record ComponentLicenseRow(
            long componentId,
            @Nullable Long licenseId,
            @Nullable String license,
            @Nullable String licenseExpression,
            @Nullable String licenseUrl,
            long ordinality,
            String acknowledgement) {

        static @Nullable ComponentLicenseRow of(Component component) {
            final License resolvedLicense = component.getResolvedLicense();
            if (resolvedLicense == null
                    && component.getLicense() == null
                    && component.getLicenseExpression() == null
                    && component.getLicenseUrl() == null) {
                return null;
            }

            return new ComponentLicenseRow(
                    component.getId(),
                    resolvedLicense != null ? resolvedLicense.getId() : null,
                    component.getLicense(),
                    component.getLicenseExpression(),
                    component.getLicenseUrl(),
                    1,
                    "DECLARED");
        }
    }

    default void replaceAll(Component component) {
        final ComponentLicenseRow row = ComponentLicenseRow.of(component);
        final List<ComponentLicenseRow> rows = row != null ? List.of(row) : List.of();
        final List<ComponentLicenseRow> existingRows =
                getLicenseRows(List.of(component.getId())).getOrDefault(component.getId(), List.of());
        if (rows.equals(existingRows)) {
            return;
        }

        getHandle()
                .createUpdate(/* language=SQL */ """
                    DELETE
                      FROM "COMPONENTLICENSES"
                     WHERE "COMPONENT_ID" = :componentId
                    """)
                .bind("componentId", component.getId())
                .execute();
        createAll(rows);
    }

    default void createAll(List<ComponentLicenseRow> rows) {
        if (rows.isEmpty()) {
            return;
        }

        getHandle()
                .createUpdate(/* language=SQL */ """
                    INSERT INTO "COMPONENTLICENSES" (
                      "COMPONENT_ID"
                    , "LICENSE_ID"
                    , "LICENSE"
                    , "LICENSE_EXPRESSION"
                    , "LICENSE_URL"
                    , "ORDINALITY"
                    , "ACKNOWLEDGEMENT"
                    )
                    SELECT *
                      FROM UNNEST(
                             :componentIds
                           , :licenseIds
                           , :licenses
                           , :licenseExpressions
                           , :licenseUrls
                           , :ordinalities
                           , :acknowledgements
                           )
                    """)
                .bindArray("componentIds", Long.class, columnValues(rows, ComponentLicenseRow::componentId))
                .bindArray("licenseIds", Long.class, columnValues(rows, ComponentLicenseRow::licenseId))
                .bindArray("licenses", String.class, columnValues(rows, ComponentLicenseRow::license))
                .bindArray(
                        "licenseExpressions", String.class, columnValues(rows, ComponentLicenseRow::licenseExpression))
                .bindArray("licenseUrls", String.class, columnValues(rows, ComponentLicenseRow::licenseUrl))
                .bindArray("ordinalities", Long.class, columnValues(rows, ComponentLicenseRow::ordinality))
                .bindArray("acknowledgements", String.class, columnValues(rows, ComponentLicenseRow::acknowledgement))
                .execute();
    }

    default Map<Long, List<ComponentLicenseRow>> getLicenseRows(Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                    SELECT cl."COMPONENT_ID"
                         , cl."LICENSE_ID"
                         , cl."LICENSE"
                         , cl."LICENSE_EXPRESSION"
                         , cl."LICENSE_URL"
                         , cl."ORDINALITY"
                         , cl."ACKNOWLEDGEMENT"
                      FROM "COMPONENTLICENSES" AS cl
                     WHERE cl."COMPONENT_ID" = ANY(:componentIds)
                     ORDER BY cl."COMPONENT_ID"
                            , cl."ORDINALITY"
                    """)
                .bindArray("componentIds", Long.class, componentIds)
                .reduceResultSet(new HashMap<>(), (result, rs, _) -> {
                    final long componentId = rs.getLong("COMPONENT_ID");
                    final Long licenseId = rs.getObject("LICENSE_ID", Long.class);

                    result.computeIfAbsent(componentId, ignored -> new ArrayList<>())
                            .add(new ComponentLicenseRow(
                                    componentId,
                                    licenseId,
                                    rs.getString("LICENSE"),
                                    rs.getString("LICENSE_EXPRESSION"),
                                    rs.getString("LICENSE_URL"),
                                    rs.getLong("ORDINALITY"),
                                    rs.getString("ACKNOWLEDGEMENT")));

                    return result;
                });
    }

    record ComponentLicenseExportRow(
            long componentId,
            @Nullable String licenseId,
            @Nullable String name,
            @Nullable String licenseExpression,
            @Nullable String licenseUrl) {}

    default Map<Long, List<ComponentLicenseExportRow>> exportAll(Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return Map.of();
        }

        return getHandle()
                .createQuery(/* language=SQL */ """
                    SELECT cl."COMPONENT_ID"
                         , CASE
                             WHEN NOT COALESCE(lic."ISCUSTOMLICENSE", FALSE)
                             THEN lic."LICENSEID"
                             END
                           AS "LICENSE_ID"
                         , COALESCE(lic."NAME", cl."LICENSE") AS "NAME"
                         , cl."LICENSE_EXPRESSION"
                         , cl."LICENSE_URL"
                      FROM "COMPONENTLICENSES" AS cl
                      LEFT JOIN "LICENSE" AS lic
                        ON lic."ID" = cl."LICENSE_ID"
                     WHERE cl."COMPONENT_ID" = ANY(:componentIds)
                     ORDER BY cl."COMPONENT_ID"
                            , cl."ORDINALITY"
                    """)
                .bindArray("componentIds", Long.class, componentIds)
                .map((rs, _) -> new ComponentLicenseExportRow(
                        rs.getLong("COMPONENT_ID"),
                        rs.getString("LICENSE_ID"),
                        rs.getString("NAME"),
                        rs.getString("LICENSE_EXPRESSION"),
                        rs.getString("LICENSE_URL")))
                .collect(Collectors.groupingBy(ComponentLicenseExportRow::componentId));
    }
}
