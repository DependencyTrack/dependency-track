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

import alpine.model.ApiKey;
import alpine.model.ServiceAccount;
import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.ServiceAccountsApi;
import org.dependencytrack.api.v2.model.CreateServiceAccountApiKeyRequest;
import org.dependencytrack.api.v2.model.CreateServiceAccountApiKeyResponse;
import org.dependencytrack.api.v2.model.CreateServiceAccountRequest;
import org.dependencytrack.api.v2.model.GetServiceAccountResponse;
import org.dependencytrack.api.v2.model.ListServiceAccountApiKeysResponse;
import org.dependencytrack.api.v2.model.ListServiceAccountsResponse;
import org.dependencytrack.api.v2.model.ServiceAccountApiKey;
import org.dependencytrack.api.v2.model.ServiceAccountTeam;
import org.dependencytrack.api.v2.model.UpdateServiceAccountRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao.ServiceAccountDetailsRow;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao.ServiceAccountRow;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao.UpdatedServiceAccountRow;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/// @since 5.2.0
@Provider
public final class ServiceAccountsResource extends AbstractApiResource implements ServiceAccountsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceAccountsResource.class);
    private static final PageTokenEncoder PAGE_TOKEN_ENCODER = new SimplePageTokenEncoder();

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createServiceAccount(CreateServiceAccountRequest request) {
        final String username = ServiceAccount.usernameOf(request.getName());

        try {
            useJdbiTransaction(handle -> handle.attach(ServiceAccountDao.class).create(username, request.getEmail()));
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException("A user with username %s already exists".formatted(username), e);
            }

            throw e;
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created service account: {}", username);
        return Response.created(getUriInfo()
                        .getBaseUriBuilder()
                        .path("/service-accounts")
                        .path(request.getName())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getServiceAccount(String name) {
        final String username = ServiceAccount.usernameOf(name);

        final ServiceAccountDetailsRow row =
                withJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).getByUsername(username));
        if (row == null) {
            throw new NotFoundException();
        }

        return Response.ok(GetServiceAccountResponse.builder()
                        .name(ServiceAccount.nameOf(row.username()))
                        .username(row.username())
                        .email(row.email())
                        .suspended(row.suspended())
                        .teams(row.teams().stream()
                                .<ServiceAccountTeam>map(team -> ServiceAccountTeam.builder()
                                        .uuid(team.uuid())
                                        .name(team.name())
                                        .build())
                                .toList())
                        .permissions(row.permissions())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response listServiceAccounts(String q, String pageToken, Integer limit) {
        final Page<ServiceAccountRow> page = withJdbiHandle(
                handle -> handle.attach(ServiceAccountDao.class).listServiceAccounts(limit, pageToken, q));

        return Response.ok(ListServiceAccountsResponse.builder()
                        .items(page.items().stream()
                                .map(ServiceAccountsResource::convert)
                                .toList())
                        .nextPageToken(page.nextPageToken())
                        .total(convertTotalCount(page.totalCount()))
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response updateServiceAccount(String name, UpdateServiceAccountRequest request) {
        final String username = ServiceAccount.usernameOf(name);

        final UpdatedServiceAccountRow updated = inJdbiTransaction(handle ->
                handle.attach(ServiceAccountDao.class).update(username, request.getEmail(), request.getSuspended()));
        if (updated == null) {
            throw new NotFoundException();
        }

        if (updated.suspendedChanged()) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    request.getSuspended() ? "Suspended service account: {}" : "Unsuspended service account: {}",
                    username);
        }
        if (updated.emailChanged()) {
            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated email of service account: {}", username);
        }

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteServiceAccount(String name) {
        final String username = ServiceAccount.usernameOf(name);

        final int deleted = inJdbiTransaction(
                handle -> handle.attach(ServiceAccountDao.class).delete(username));
        if (deleted == 0) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted service account: {}", username);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createServiceAccountApiKey(String name, CreateServiceAccountApiKeyRequest request) {
        final String username = ServiceAccount.usernameOf(name);

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final ServiceAccount serviceAccount = qm.getServiceAccount(username);
            if (serviceAccount == null) {
                throw new NotFoundException();
            }
            if (serviceAccount.isSuspended()) {
                throw new ClientErrorException("The service account is suspended", Response.Status.CONFLICT);
            }

            final ApiKey apiKey = qm.createApiKey(serviceAccount, request.getComment());
            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created API key for service account: {}", username);

            return Response.created(getUriInfo()
                            .getBaseUriBuilder()
                            .path("/service-accounts")
                            .path(name)
                            .path("api-keys")
                            .path(apiKey.getPublicId())
                            .build())
                    .entity(CreateServiceAccountApiKeyResponse.builder()
                            .publicId(apiKey.getPublicId())
                            .key(apiKey.getKey())
                            .build())
                    .build();
        }
    }

    record ListApiKeysPageToken(long lastId) implements PageToken {}

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response listServiceAccountApiKeys(String name, String pageToken, Integer limit) {
        final ListApiKeysPageToken decodedPageToken = PAGE_TOKEN_ENCODER.decode(pageToken, ListApiKeysPageToken.class);

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final ServiceAccount serviceAccount = qm.getServiceAccount(ServiceAccount.usernameOf(name));
            if (serviceAccount == null) {
                throw new NotFoundException();
            }

            // TODO: Move this to JDBI and paginate in the database.
            //  Using JDO initially since API v1 endpoints for API keys are also still on JDO,
            //  and wanting to avoid multiple code paths for the same thing. All API key paths
            //  should be migrated in one go, eventually. For the moment this solution is fine
            //  because we don't anticipate service accounts to have many API keys.
            final List<ApiKey> allApiKeys = qm.getApiKeys(serviceAccount);
            final List<ApiKey> remainingApiKeys = allApiKeys.stream()
                    .filter(apiKey -> decodedPageToken == null || apiKey.getId() < decodedPageToken.lastId())
                    .toList();
            final List<ApiKey> pageApiKeys = remainingApiKeys.subList(0, Math.min(limit, remainingApiKeys.size()));
            final ListApiKeysPageToken nextPageToken = remainingApiKeys.size() > limit
                    ? new ListApiKeysPageToken(pageApiKeys.getLast().getId())
                    : null;

            return Response.ok(ListServiceAccountApiKeysResponse.builder()
                            .items(pageApiKeys.stream()
                                    .<ServiceAccountApiKey>map(apiKey -> ServiceAccountApiKey.builder()
                                            .publicId(apiKey.getPublicId())
                                            .comment(apiKey.getComment())
                                            .createdAt(
                                                    apiKey.getCreated() != null
                                                            ? apiKey.getCreated()
                                                                    .getTime()
                                                            : null)
                                            .lastUsedAt(
                                                    apiKey.getLastUsed() != null
                                                            ? apiKey.getLastUsed()
                                                                    .getTime()
                                                            : null)
                                            .build())
                                    .toList())
                            .nextPageToken(PAGE_TOKEN_ENCODER.encode(nextPageToken))
                            .total(convertTotalCount(new TotalCount(allApiKeys.size(), TotalCount.Type.EXACT)))
                            .build())
                    .build();
        }
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteServiceAccountApiKey(String name, String publicId) {
        final String username = ServiceAccount.usernameOf(name);

        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.runInTransaction(() -> {
                final ApiKey apiKey = qm.getApiKeyByPublicId(publicId);
                if (apiKey == null
                        || apiKey.getUser() == null
                        || !username.equals(apiKey.getUser().getUsername())) {
                    throw new NotFoundException();
                }

                qm.delete(apiKey);
            });
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted API key {} of service account: {}", publicId, username);
        return Response.noContent().build();
    }

    private static org.dependencytrack.api.v2.model.ServiceAccount convert(ServiceAccountRow row) {
        return org.dependencytrack.api.v2.model.ServiceAccount.builder()
                .name(ServiceAccount.nameOf(row.username()))
                .username(row.username())
                .email(row.email())
                .suspended(row.suspended())
                .build();
    }
}
