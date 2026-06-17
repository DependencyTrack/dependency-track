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
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.SecretsApi;
import org.dependencytrack.api.v2.model.CreateSecretRequest;
import org.dependencytrack.api.v2.model.ListSecretsResponse;
import org.dependencytrack.api.v2.model.UpdateSecretRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class SecretsResource extends AbstractApiResource implements SecretsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecretsResource.class);

    @Inject
    private SecretManager secretManager;

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_CREATE
    })
    public Response createSecret(final CreateSecretRequest request) {
        try {
            secretManager.createSecret(
                    request.getName(),
                    request.getDescription(),
                    request.getValue());
        } catch (SecretAlreadyExistsException e) {
            throw new AlreadyExistsException(e.getMessage(), e);
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created secret: {}", request.getName());
        return Response
                .created(getUriInfo().getBaseUriBuilder()
                        .path("/secrets")
                        .path(request.getName())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_UPDATE
    })
    public Response updateSecret(final String name, final UpdateSecretRequest request) {
        final boolean updated;
        try {
            updated = secretManager.updateSecret(
                    name,
                    request.getDescription(),
                    request.getValue());
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }
        if (!updated) {
            return Response.notModified().build();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated secret: {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_DELETE
    })
    public Response deleteSecret(final String name) {
        try {
            secretManager.deleteSecret(name);
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted secret: {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getSecretMetadata(String name) {
        final SecretMetadata secretMetadata = secretManager.getSecretMetadata(name);
        if (secretMetadata == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(secretMetadata)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listSecretMetadata(String q, String pageToken, Integer limit) {
        final Page<SecretMetadata> secretsPage = secretManager.listSecretMetadata(
                new ListSecretsRequest()
                        .withSearchText(q)
                        .withPageToken(pageToken)
                        .withLimit(limit));

        final var response = ListSecretsResponse.builder()
                .items(
                        secretsPage.items().stream()
                                .map(this::convert)
                                .toList())
                .nextPageToken(secretsPage.nextPageToken())
                .total(convertTotalCount(secretsPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    private org.dependencytrack.api.v2.model.SecretMetadata convert(SecretMetadata secretMetadata) {
        return org.dependencytrack.api.v2.model.SecretMetadata.builder()
                .name(secretMetadata.name())
                .description(secretMetadata.description())
                .createdAt(secretMetadata.createdAt() != null
                        ? secretMetadata.createdAt().toEpochMilli()
                        : null)
                .updatedAt(secretMetadata.updatedAt() != null
                        ? secretMetadata.updatedAt().toEpochMilli()
                        : null)
                .build();
    }

}
