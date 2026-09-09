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
import org.dependencytrack.api.v2.VulnsApi;
import org.dependencytrack.api.v2.model.KevAssertion;
import org.dependencytrack.api.v2.model.ListVulnKevAssertionsResponse;
import org.dependencytrack.api.v2.model.TotalCount;
import org.dependencytrack.api.v2.model.TotalCountType;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.persistence.jdbi.KevDao;
import org.dependencytrack.persistence.jdbi.KevDao.KevAssertionRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityDao;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.resources.AbstractApiResource;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// @since 5.1.0
@Provider
public final class VulnsResource extends AbstractApiResource implements VulnsApi {

    private final PluginManager pluginManager;

    @Inject
    VulnsResource(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listVulnKevAssertions(String source, String vulnId) {
        final List<KevAssertionRow> rows = withJdbiHandle(getAlpineRequest(), handle -> {
            if (!handle.attach(VulnerabilityDao.class).existsByVulnIdAndSource(vulnId, source)) {
                throw new NotFoundException();
            }

            return handle.attach(KevDao.class).getAssertions(source, vulnId);
        });

        final Map<String, String> displayNameByExtensionName = pluginManager.getFactories(KevDataSource.class).stream()
                .collect(Collectors.toMap(ExtensionFactory::extensionName, ExtensionFactory::displayName));

        final var items = new ArrayList<KevAssertion>(rows.size());
        for (final KevAssertionRow row : rows) {
            items.add(KevAssertion.builder()
                    .asserter(row.asserter())
                    .asserterDisplayName(displayNameByExtensionName.getOrDefault(row.asserter(), row.asserter()))
                    .vulnSource(row.vulnSource())
                    .vulnId(row.vulnId())
                    .publishedAt(row.publishedAt() != null ? row.publishedAt().toEpochMilli() : null)
                    .requiredAction(row.requiredAction())
                    .knownRansomware(row.knownRansomware())
                    .description(row.description())
                    .createdAt(row.createdAt().toEpochMilli())
                    .updatedAt(row.updatedAt().toEpochMilli())
                    .build());
        }

        final var response = ListVulnKevAssertionsResponse.builder()
                .items(items)
                .total(TotalCount.builder()
                        .count((long) items.size())
                        .type(TotalCountType.EXACT)
                        .build())
                .build();
        return Response.ok(response).build();
    }
}
