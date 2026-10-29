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
import org.dependencytrack.api.v2.SamlUsersApi;
import org.dependencytrack.api.v2.model.CreateSamlUserRequest;
import org.dependencytrack.api.v2.model.ListSamlUsersResponse;
import org.dependencytrack.api.v2.model.SamlUser;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.saml.SamlDao;
import org.dependencytrack.auth.saml.SamlDao.SamlUserRow;
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

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/// @since 5.3.0
@Provider
@NullMarked
public final class SamlUsersResource extends AbstractApiResource implements SamlUsersApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlUsersResource.class);

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response listSamlUsers(@Nullable String q, @Nullable String pageToken, Integer limit) {
        final Page<SamlUserRow> page =
                withJdbiHandle(handle -> handle.attach(SamlDao.class).listUsers(limit, pageToken, trimToNull(q)));

        return Response.ok(ListSamlUsersResponse.builder()
                        .items(page.items().stream()
                                .<SamlUser>map(row -> SamlUser.builder()
                                        .username(row.username())
                                        .email(row.email())
                                        .teams(SamlGroupsResource.convert(row.teams()))
                                        .permissions(row.permissions())
                                        .build())
                                .toList())
                        .nextPageToken(page.nextPageToken())
                        .total(convertTotalCount(page.totalCount()))
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createSamlUser(CreateSamlUserRequest request) {
        // The reserved service account prefix is refused by the request schema.
        final String username = request.getUsername();

        try {
            inJdbiTransaction(
                    handle -> handle.attach(SamlDao.class).createUser(username, trimToNull(request.getEmail())));
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException("A user with username %s already exists".formatted(username), e);
            }
            throw e;
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created SAML user: {}", username);
        return Response.created(getUriInfo()
                        .getBaseUriBuilder()
                        .path("/saml-users")
                        .path(username)
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteSamlUser(String username) {
        final int deleted =
                inJdbiTransaction(handle -> handle.attach(SamlDao.class).deleteUser(username));
        if (deleted == 0) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted SAML user: {}", username);
        return Response.noContent().build();
    }
}
