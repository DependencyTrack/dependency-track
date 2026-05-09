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
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.api.v2.ComponentsApi;
import org.dependencytrack.api.v2.model.CreateComponentRequest;
import org.dependencytrack.api.v2.model.ListComponentsResponse;
import org.dependencytrack.api.v2.model.ListComponentsResponseItem;
import org.dependencytrack.api.v2.model.ProjectState;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.exception.ProjectAccessDeniedException;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapDependencyMetrics;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapHashes;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapOrganizationalContacts;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapProject;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapScope;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapSortDirection;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

@Provider
public class ComponentsResource extends AbstractApiResource implements ComponentsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentsResource.class);

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response createComponent(final CreateComponentRequest request) {
        final UUID projectUuid = request.getProjectUuid();
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new NotFoundException();
                }
                try {
                    requireAccess(qm, project);
                } catch (ProjectAccessDeniedException ex) {
                    throw new NotAuthorizedException(Response.Status.UNAUTHORIZED);
                }
                return mapRequestToComponent(request, qm, project);
            });

            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Component created: {}", request.getName());
            return Response
                    .created(uriInfo.getBaseUriBuilder()
                            .path("/components")
                            .path(component.getUuid().toString())
                            .build())
                    .build();
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new ClientErrorException(Response.Status.CONFLICT);
            }
            throw e;
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponents(String groupContains, String nameContains, String versionContains, String purlPrefix, String cpe,
                                   String swidTagIdContains, String hashType, String hash, ProjectState projectState, Boolean projectLatestVersion,
                                   Integer limit, String pageToken, SortDirection sortDirection, String sortBy) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            PackageURL packageURL = null;
            if (purlPrefix != null) {
                try {
                    packageURL = new PackageURL(StringUtils.trimToNull(purlPrefix));
                } catch (MalformedPackageURLException e) {
                    throw new BadRequestException("Invalid package URL: %s".formatted(purlPrefix));
                }
            }
            if (cpe != null) {
                try {
                    CpeParser.parse(StringUtils.trimToNull(cpe));
                } catch (CpeParsingException e) {
                    throw new BadRequestException("Invalid CPE: %s".formatted(cpe));
                }
            }
            ComponentDao.HashType hashTypeEnum = null;
            if (hashType != null) {
                try {
                    hashTypeEnum = ComponentDao.HashType.valueOf(StringUtils.trimToNull(hashType).toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException("Invalid Hash type: %s".formatted(hashType));
                }
            }

            final Page<Component> componentsPage = handle.attach(ComponentDao.class)
                    .listComponents(
                            /* projectId */ null,
                            /* includeMetrics */ true,
                            packageURL != null ? packageURL.canonicalize().toLowerCase() : null,
                            StringUtils.trimToNull(cpe),
                            StringUtils.trimToNull(swidTagIdContains),
                            StringUtils.trimToNull(groupContains),
                            StringUtils.trimToNull(nameContains),
                            StringUtils.trimToNull(versionContains),
                            hashTypeEnum,
                            StringUtils.trimToNull(hash),
                            switch (projectState) {
                                case ACTIVE -> Boolean.TRUE;
                                case INACTIVE -> Boolean.FALSE;
                                case null -> null;
                            },
                            projectLatestVersion,
                            limit,
                            pageToken,
                            sortBy,
                            mapSortDirection(sortDirection));

            final var response = ListComponentsResponse.builder()
                    .items(componentsPage.items().stream()
                            .<ListComponentsResponseItem>map(
                                    componentRow -> ListComponentsResponseItem.builder()
                                            .name(componentRow.getName())
                                            .hashes(mapHashes(componentRow))
                                            .classifier(componentRow.getClassifier() != null ? componentRow.getClassifier().name() : null)
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
                                            .purl(componentRow.getPurl() != null ? componentRow.getPurl().toString() : null)
                                            .swidTagId(componentRow.getSwidTagId())
                                            .uuid(componentRow.getUuid())
                                            .version(componentRow.getVersion())
                                            .project(mapProject(componentRow.getProject()))
                                            .metrics(mapDependencyMetrics(componentRow.getMetrics()))
                                            .build())
                            .toList())
                    .nextPageToken(componentsPage.nextPageToken())
                    .total(convertTotalCount(componentsPage.totalCount()))
                    .build();
            return Response.ok(response).build();
        });
    }

    private Component mapRequestToComponent(CreateComponentRequest request, QueryManager qm, Project project) {
        final License resolvedLicense = qm.getLicense(request.getLicense());
        final Component component = new Component();
        component.setProject(project);
        if (request.getAuthors() != null) {
            component.setAuthors(mapOrganizationalContacts(request.getAuthors()));
        }
        component.setPublisher(StringUtils.trimToNull(request.getPublisher()));
        component.setName(StringUtils.trimToNull(request.getName()));
        component.setVersion(StringUtils.trimToNull(request.getVersion()));
        component.setGroup(StringUtils.trimToNull(request.getGroup()));
        component.setDescription(StringUtils.trimToNull(request.getDescription()));
        component.setFilename(StringUtils.trimToNull(request.getFilename()));
        if (request.getClassifier() != null) {
            component.setClassifier(Classifier.valueOf(request.getClassifier().name()));
        }
        component.setPurl(request.getPurl());
        component.setPurlCoordinates(PurlUtil.silentPurlCoordinatesOnly(component.getPurl()));
        component.setInternal(new InternalComponentIdentifier().isInternal(component));
        component.setCpe(StringUtils.trimToNull(request.getCpe()));
        component.setSwidTagId(StringUtils.trimToNull(request.getSwidTagId()));
        component.setCopyright(StringUtils.trimToNull(request.getCopyright()));
        if (request.getHashes() != null) {
            component.setMd5(StringUtils.trimToNull(request.getHashes().getMd5()));
            component.setSha1(StringUtils.trimToNull(request.getHashes().getSha1()));
            component.setSha256(StringUtils.trimToNull(request.getHashes().getSha256()));
            component.setSha384(StringUtils.trimToNull(request.getHashes().getSha384()));
            component.setSha512(StringUtils.trimToNull(request.getHashes().getSha512()));
            component.setSha3_256(StringUtils.trimToNull(request.getHashes().getSha3256()));
            component.setSha3_384(StringUtils.trimToNull(request.getHashes().getSha3384()));
            component.setSha3_512(StringUtils.trimToNull(request.getHashes().getSha3512()));
        }
        if (resolvedLicense != null) {
            component.setLicense(null);
            component.setLicenseExpression(null);
            component.setLicenseUrl(StringUtils.trimToNull(request.getLicenseUrl()));
            component.setResolvedLicense(resolvedLicense);
        } else if (StringUtils.isNotBlank(request.getLicense())) {
            component.setLicense(StringUtils.trim(request.getLicense()));
            component.setLicenseExpression(null);
            component.setLicenseUrl(StringUtils.trimToNull(request.getLicenseUrl()));
            component.setResolvedLicense(null);
        } else if (StringUtils.isNotBlank(request.getLicenseExpression())) {
            component.setLicense(null);
            component.setLicenseExpression(StringUtils.trim(request.getLicenseExpression()));
            component.setLicenseUrl(null);
            component.setResolvedLicense(null);
        }
        component.setNotes(StringUtils.trimToNull(request.getNotes()));

        qm.createComponent(component, true);

        return component;
    }
}
