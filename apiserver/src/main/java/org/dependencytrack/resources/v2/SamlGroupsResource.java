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
import org.dependencytrack.api.v2.SamlGroupsApi;
import org.dependencytrack.api.v2.model.CreateSamlGroupRequest;
import org.dependencytrack.api.v2.model.ListSamlGroupsResponse;
import org.dependencytrack.api.v2.model.SamlGroup;
import org.dependencytrack.api.v2.model.SamlGroupTeam;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.saml.SamlDao;
import org.dependencytrack.auth.saml.SamlDao.SamlGroupRow;
import org.dependencytrack.auth.saml.SamlDao.TeamRef;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/// @since 5.3.0
@Provider
@NullMarked
public final class SamlGroupsResource extends AbstractApiResource implements SamlGroupsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlGroupsResource.class);

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response listSamlGroups(@Nullable UUID teamUuid, @Nullable String pageToken, Integer limit) {
        final Page<SamlGroupRow> page = withJdbiHandle(handle -> handle.attach(SamlDao.class)
                .listGroups(limit, pageToken, teamUuid != null ? teamUuid.toString() : null));

        return Response.ok(ListSamlGroupsResponse.builder()
                        .items(page.items().stream()
                                .<SamlGroup>map(row -> SamlGroup.builder()
                                        .uuid(row.uuid())
                                        .name(row.name())
                                        .teams(convert(row.teams()))
                                        .build())
                                .toList())
                        .nextPageToken(page.nextPageToken())
                        .total(convertTotalCount(page.totalCount()))
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createSamlGroup(CreateSamlGroupRequest request) {
        final UUID uuid;
        try {
            uuid = inJdbiTransaction(handle -> handle.attach(SamlDao.class).createGroup(request.getName()));
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException(
                        "A SAML group with name %s already exists".formatted(request.getName()), e);
            }
            throw e;
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created SAML group: {}", request.getName());
        return Response.created(getUriInfo()
                        .getBaseUriBuilder()
                        .path("/saml-groups")
                        .path(uuid.toString())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteSamlGroup(UUID uuid) {
        final int deleted =
                inJdbiTransaction(handle -> handle.attach(SamlDao.class).deleteGroup(uuid));
        if (deleted == 0) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted SAML group: {}", uuid);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response updateSamlGroupMapping(UUID uuid, UUID teamUuid) {
        final boolean created = inJdbiTransaction(handle -> {
            final var dao = handle.attach(SamlDao.class);
            if (!dao.groupAndTeamExist(uuid, teamUuid.toString())) {
                throw new NotFoundException();
            }
            return dao.createMapping(uuid, teamUuid.toString()) > 0;
        });

        if (created) {
            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Mapped SAML group {} to team {}", uuid, teamUuid);
        }
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response deleteSamlGroupMapping(UUID uuid, UUID teamUuid) {
        final int deleted =
                inJdbiTransaction(handle -> handle.attach(SamlDao.class).deleteMapping(uuid, teamUuid.toString()));
        if (deleted == 0) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Removed mapping of SAML group {} to team {}", uuid, teamUuid);
        return Response.noContent().build();
    }

    static List<SamlGroupTeam> convert(List<TeamRef> teams) {
        return teams.stream()
                .<SamlGroupTeam>map(team -> SamlGroupTeam.builder()
                        .uuid(UUID.fromString(team.uuid()))
                        .name(team.name())
                        .build())
                .toList();
    }
}
