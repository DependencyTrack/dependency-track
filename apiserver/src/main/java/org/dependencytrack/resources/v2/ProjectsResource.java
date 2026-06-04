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
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ProjectsApi;
import org.dependencytrack.api.v2.model.CloneProjectInclude;
import org.dependencytrack.api.v2.model.CloneProjectRequest;
import org.dependencytrack.api.v2.model.CloneProjectResponse;
import org.dependencytrack.api.v2.model.ListProjectComponentsResponse;
import org.dependencytrack.api.v2.model.ListProjectComponentsResponseItem;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.jdbi.query.ListProjectComponentsQuery;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.dependencytrack.resources.v2.exception.ProblemType;
import org.dependencytrack.util.PurlUtil;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.map;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapDependencyMetrics;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapHashes;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapScope;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapSortDirection;

@Provider
public class ProjectsResource extends AbstractApiResource implements ProjectsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectsResource.class);

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listProjectComponents(
            UUID uuid,
            Boolean onlyOutdated,
            Boolean onlyDirect,
            String q,
            List<String> expand,
            Integer limit,
            String pageToken,
            SortDirection sortDirection,
            String sortBy) {
        final boolean hasExpand = expand != null && !expand.isEmpty();
        final boolean expandMetrics = hasExpand && expand.contains("metrics");
        final boolean expandPkgMeta = hasExpand && expand.contains("package_metadata");
        final boolean expandPkgArtifactMeta = hasExpand && expand.contains("package_artifact_metadata");
        final boolean expandOccurrenceCount = hasExpand && expand.contains("occurrence_count");

        return inJdbiTransaction(getAlpineRequest(), handle -> {
            final Long projectId = handle.attach(ProjectDao.class).getProjectId(uuid);
            if (projectId == null) {
                throw new NotFoundException();
            }
            requireProjectAccess(handle, uuid);

            final ListProjectComponentsQuery.SortBy sortByEnum = switch (sortBy) {
                case null -> null;
                case "name" -> ListProjectComponentsQuery.SortBy.NAME;
                case "group" -> ListProjectComponentsQuery.SortBy.GROUP;
                case "last_inherited_risk_score" -> ListProjectComponentsQuery.SortBy.LAST_RISKSCORE;
                case "package_artifact_metadata.published_at" -> ListProjectComponentsQuery.SortBy.PUBLISHED_AT;
                default -> throw ProblemDetailsException.of(ProblemType.INVALID_SORT_BY, "Invalid sort_by: " + sortBy);
            };

            final Page<Component> componentsPage = handle
                    .attach(ComponentDao.class)
                    .listProjectComponents(new ListProjectComponentsQuery(
                            projectId,
                            onlyOutdated,
                            onlyDirect,
                            /* searchText */ q,
                            expandOccurrenceCount,
                            limit,
                            pageToken,
                            sortByEnum,
                            mapSortDirection(sortDirection)));

            var metricsByComponentId = Map.<Long, DependencyMetrics>of();
            var pkgMetaByPackagePurl = Map.<String, PackageMetadata>of();
            var pkgArtifactMetaByPurl = Map.<String, PackageArtifactMetadata>of();

            if (!componentsPage.items().isEmpty()) {
                if (expandMetrics) {
                    final Set<Long> componentIds =
                            componentsPage.items().stream()
                                    .map(Component::getId)
                                    .collect(Collectors.toSet());
                    metricsByComponentId = handle
                            .attach(MetricsDao.class)
                            .getMostRecentDependencyMetrics(componentIds).stream()
                            .collect(Collectors.toMap(
                                    DependencyMetrics::getComponentId,
                                    Function.identity()));
                }
                if (expandPkgMeta) {
                    final Set<String> packagePurls =
                            componentsPage.items().stream()
                                    .filter(component -> component.getPurl() != null)
                                    .map(component -> PurlUtil.purlPackageOnly(component.getPurl()))
                                    .collect(Collectors.toSet());
                    pkgMetaByPackagePurl =
                            new PackageMetadataDao(handle).getAll(packagePurls).stream()
                                    .collect(Collectors.toMap(
                                            pm -> pm.purl().canonicalize(),
                                            Function.identity()));
                }
                if (expandPkgArtifactMeta) {
                    final Set<String> versionedPurls =
                            componentsPage.items().stream()
                                    .filter(component -> component.getPurl() != null)
                                    .map(component -> component.getPurl().canonicalize())
                                    .collect(Collectors.toSet());
                    pkgArtifactMetaByPurl =
                            new PackageArtifactMetadataDao(handle).getAll(versionedPurls).stream()
                                    .collect(Collectors.toMap(
                                            pam -> pam.purl().canonicalize(),
                                            Function.identity()));
                }
            }

            final var responseItems = new ArrayList<ListProjectComponentsResponseItem>(componentsPage.items().size());
            for (final Component componentRow : componentsPage.items()) {
                final String purlStr = componentRow.getPurl() != null
                        ? componentRow.getPurl().canonicalize()
                        : null;
                final String packagePurlStr = componentRow.getPurl() != null
                        ? PurlUtil.purlPackageOnly(componentRow.getPurl())
                        : null;
                final PackageArtifactMetadata pkgArtifactMeta = purlStr != null
                        ? pkgArtifactMetaByPurl.get(purlStr)
                        : null;
                final var responseItem = ListProjectComponentsResponseItem.builder()
                        .name(componentRow.getName())
                        .hashes(mapHashes(componentRow))
                        .classifier(componentRow.getClassifier() != null
                                ? componentRow.getClassifier().name()
                                : null)
                        .scope(mapScope(componentRow.getScope()))
                        .copyright(componentRow.getCopyright())
                        .cpe(componentRow.getCpe())
                        .group(componentRow.getGroup())
                        .internal(componentRow.isInternal())
                        .lastInheritedRiskScore(componentRow.getLastInheritedRiskScore())
                        .license(componentRow.getLicense())
                        .licenseExpression(componentRow.getLicenseExpression())
                        .licenseUrl(componentRow.getLicenseUrl())
                        .resolvedLicense(mapLicense(componentRow.getResolvedLicense()))
                        .occurrenceCount(expandOccurrenceCount
                                ? componentRow.getOccurrenceCount()
                                : null)
                        .purl(purlStr)
                        .swidTagId(componentRow.getSwidTagId())
                        .uuid(componentRow.getUuid())
                        .version(componentRow.getVersion())
                        .metrics(expandMetrics
                                ? mapDependencyMetrics(metricsByComponentId.get(componentRow.getId()))
                                : null)
                        .packageMetadata(expandPkgMeta && packagePurlStr != null
                                ? map(pkgMetaByPackagePurl.get(packagePurlStr))
                                : null)
                        .packageArtifactMetadata(expandPkgArtifactMeta
                                ? map(pkgArtifactMeta)
                                : null)
                        .build();
                responseItems.add(responseItem);
            }

            final var response = ListProjectComponentsResponse.builder()
                    .items(responseItems)
                    .nextPageToken(componentsPage.nextPageToken())
                    .total(convertTotalCount(componentsPage.totalCount()))
                    .build();
            return Response.ok(response).build();
        });
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE
    })
    public Response cloneProject(final UUID projectUuid, final CloneProjectRequest request) {
        final UUID clonedProjectUuid = inJdbiTransaction(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, projectUuid);

            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Cloning project {} to version {}",
                    projectUuid,
                    request.getVersion());

            final UUID uuid = handle.attach(ProjectDao.class).cloneProject(
                    new CloneProjectCommand(
                            projectUuid,
                            request.getVersion(),
                            request.getVersionIsLatest(),
                            request.getIncludes().contains(CloneProjectInclude.ACL),
                            request.getIncludes().contains(CloneProjectInclude.COMPONENTS),
                            request.getIncludes().contains(CloneProjectInclude.FINDINGS),
                            request.getIncludes().contains(CloneProjectInclude.FINDINGS_AUDIT_HISTORY),
                            request.getIncludes().contains(CloneProjectInclude.POLICY_VIOLATIONS),
                            request.getIncludes().contains(CloneProjectInclude.POLICY_VIOLATIONS_AUDIT_HISTORY),
                            request.getIncludes().contains(CloneProjectInclude.PROPERTIES),
                            request.getIncludes().contains(CloneProjectInclude.SERVICES),
                            request.getIncludes().contains(CloneProjectInclude.TAGS)));

            requireProjectAccess(handle, uuid);
            handle.attach(MetricsDao.class).updateProjectMetrics(uuid);
            return uuid;
        });

        return Response
                .created(uriInfo.getBaseUriBuilder()
                        .path("/projects")
                        .path(clonedProjectUuid.toString())
                        .build())
                .entity(CloneProjectResponse.builder()
                        .uuid(clonedProjectUuid)
                        .build())
                .build();
    }

}
