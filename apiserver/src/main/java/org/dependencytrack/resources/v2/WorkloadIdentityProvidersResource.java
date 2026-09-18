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
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSetParseException;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.dependencytrack.api.v2.WorkloadIdentityProvidersApi;
import org.dependencytrack.api.v2.model.CreateWorkloadIdentityProviderRequest;
import org.dependencytrack.api.v2.model.ListWorkloadIdentityProvidersResponse;
import org.dependencytrack.api.v2.model.UpdateWorkloadIdentityProviderRequest;
import org.dependencytrack.api.v2.model.WorkloadIdentityProviderType;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.workloadidentity.SpiffeTrustDomain;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityKeySetFetcher;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProvider;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao.WorkloadIdentityProviderRow;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.support.jdbi.exception.UniqueConstraintViolationException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// @since 5.2.0
@Provider
@NullMarked
public final class WorkloadIdentityProvidersResource extends AbstractApiResource
        implements WorkloadIdentityProvidersApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkloadIdentityProvidersResource.class);

    private final WorkloadIdentityKeySetFetcher keySetFetcher =
            new WorkloadIdentityKeySetFetcher(HttpClient.NO_REDIRECT_INSTANCE);

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_CREATE})
    public Response createWorkloadIdentityProvider(CreateWorkloadIdentityProviderRequest request) {
        if (request.getType() == WorkloadIdentityProviderType.SPIFFE) {
            requireTrustDomain(request.getIssuer());
        }

        final String jwks = parseInlineJwks(request.getJwksUrl(), request.getJwks());
        final String jwksUrl;
        if (jwks != null) {
            jwksUrl = null;
        } else if (request.getJwksUrl() != null) {
            jwksUrl = verifiedKeySetUrl(request.getJwksUrl());
        } else if (request.getType() == WorkloadIdentityProviderType.OIDC) {
            jwksUrl = discoveredKeySetUrl(request.getIssuer());
        } else {
            throw new ClientErrorException("SPIFFE providers require jwks_url or jwks", Response.Status.BAD_REQUEST);
        }

        try {
            useJdbiTransaction(
                    getAlpineRequest(),
                    handle -> handle.attach(WorkloadIdentityProviderDao.class)
                            .create(
                                    request.getName(),
                                    switch (request.getType()) {
                                        case OIDC -> WorkloadIdentityProvider.Type.OIDC;
                                        case SPIFFE -> WorkloadIdentityProvider.Type.SPIFFE;
                                    },
                                    request.getIssuer(),
                                    request.getAudience(),
                                    jwksUrl,
                                    jwks,
                                    request.getSessionLifetimeSeconds()));
        } catch (UniqueConstraintViolationException e) {
            throw new AlreadyExistsException(
                    "A workload identity provider named %s already exists".formatted(request.getName()), e);
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Created workload identity provider {} for issuer {} with keys from {}",
                request.getName(),
                request.getIssuer(),
                jwksUrl != null ? jwksUrl : "the request");
        return Response.created(getUriInfo()
                        .getBaseUriBuilder()
                        .path("/workload-identity-providers")
                        .path(request.getName())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getWorkloadIdentityProvider(String name) {
        final WorkloadIdentityProviderRow row = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(WorkloadIdentityProviderDao.class).getByName(name));
        if (row == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(row)).build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response listWorkloadIdentityProviders(String q, String pageToken, Integer limit) {
        final Page<WorkloadIdentityProviderRow> page = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(WorkloadIdentityProviderDao.class).listProviders(limit, pageToken, q));

        return Response.ok(ListWorkloadIdentityProvidersResponse.builder()
                        .items(page.items().stream()
                                .map(WorkloadIdentityProvidersResource::convert)
                                .toList())
                        .nextPageToken(page.nextPageToken())
                        .total(convertTotalCount(page.totalCount()))
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response updateWorkloadIdentityProvider(String name, UpdateWorkloadIdentityProviderRequest request) {
        final String jwks = parseInlineJwks(request.getJwksUrl(), request.getJwks());
        String jwksUrl = request.getJwksUrl() != null ? verifiedKeySetUrl(request.getJwksUrl()) : null;
        if (request.getIssuer() != null) {
            final WorkloadIdentityProviderRow current = withJdbiHandle(
                    getAlpineRequest(),
                    handle -> handle.attach(WorkloadIdentityProviderDao.class).getByName(name));
            if (current == null) {
                throw new NotFoundException();
            }

            switch (current.type()) {
                case SPIFFE -> requireTrustDomain(request.getIssuer());
                case OIDC -> {
                    if (jwksUrl == null
                            && jwks == null
                            && current.jwksUrl() != null
                            && !current.issuer().equals(request.getIssuer())) {
                        jwksUrl = discoveredKeySetUrl(request.getIssuer());
                    }
                }
            }
        }

        final String newJwksUrl = jwksUrl;
        final boolean updated = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(WorkloadIdentityProviderDao.class)
                        .update(
                                name,
                                request.getIssuer(),
                                request.getAudience(),
                                newJwksUrl,
                                jwks,
                                request.getSessionLifetimeSeconds()));
        if (!updated) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated workload identity provider {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response deleteWorkloadIdentityProvider(String name) {
        final boolean deleted = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(WorkloadIdentityProviderDao.class).delete(name));
        if (!deleted) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted workload identity provider {}", name);
        return Response.noContent().build();
    }

    private String verifiedKeySetUrl(String jwksUrl) {
        try {
            keySetFetcher.fetchKeySet(jwksUrl);
            return jwksUrl;
        } catch (KeySourceException e) {
            throw new ClientErrorException(e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE, e);
        }
    }

    private String discoveredKeySetUrl(String issuer) {
        try {
            return verifiedKeySetUrl(keySetFetcher.resolveJwksUri(issuer));
        } catch (KeySourceException | GeneralException e) {
            throw new ClientErrorException(e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE, e);
        }
    }

    private static void requireTrustDomain(String issuer) {
        if (!SpiffeTrustDomain.isValid(issuer)) {
            throw new ClientErrorException(
                    "The issuer of a SPIFFE provider must be a trust domain such as example.org, without spiffe://",
                    Response.Status.BAD_REQUEST);
        }
    }

    private static @Nullable String parseInlineJwks(@Nullable String jwksUrl, @Nullable Map<String, Object> jwks) {
        // The generated request models default jwks to an empty map, so an absent field and {} look the same.
        if (jwks == null || jwks.isEmpty()) {
            return null;
        }
        if (jwksUrl != null) {
            throw new ClientErrorException("Provide either jwks_url or jwks, not both", Response.Status.BAD_REQUEST);
        }

        try {
            return WorkloadIdentityKeySetFetcher.parsePublicKeySet(JSONObjectUtils.toJSONString(jwks))
                    .toString();
        } catch (JWKSetParseException e) {
            throw new ClientErrorException(e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    private static org.dependencytrack.api.v2.model.WorkloadIdentityProvider convert(WorkloadIdentityProviderRow row) {
        return org.dependencytrack.api.v2.model.WorkloadIdentityProvider.builder()
                .name(row.name())
                .type(
                        switch (row.type()) {
                            case OIDC -> WorkloadIdentityProviderType.OIDC;
                            case SPIFFE -> WorkloadIdentityProviderType.SPIFFE;
                        })
                .issuer(row.issuer())
                .audience(row.audience())
                .jwksUrl(row.jwksUrl())
                .jwksKeyIds(row.jwksKeyIds())
                .sessionLifetimeSeconds(row.sessionLifetimeSeconds())
                .createdAt(row.createdAt().toEpochMilli())
                .build();
    }
}
