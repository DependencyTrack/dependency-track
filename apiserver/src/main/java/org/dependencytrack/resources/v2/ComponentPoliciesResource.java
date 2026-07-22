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
import dev.cel.common.CelValidationException;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ComponentPoliciesApi;
import org.dependencytrack.api.v2.model.ComponentPolicy;
import org.dependencytrack.api.v2.model.ListComponentPoliciesResponse;
import org.dependencytrack.api.v2.model.UpsertComponentPolicyRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.policy.cel.CelPolicyCompiler;
import org.dependencytrack.policy.cel.CelPolicyType;

import java.util.List;
import java.util.Objects;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * REST resource for component policies (automated license curation rules).
 */
@Provider
public final class ComponentPoliciesResource extends AbstractApiResource implements ComponentPoliciesApi {

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response listComponentPolicies() {
        final List<ComponentPolicyDao.ComponentPolicy> policies = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getAll());
        try (final var qm = new QueryManager()) {
            return Response.ok(ListComponentPoliciesResponse.builder()
                    .policies(policies.stream()
                            .<ComponentPolicy>map(policy -> mapPolicy(qm, policy))
                            .toList())
                    .build()).build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createComponentPolicy(final UpsertComponentPolicyRequest request) {
        validateCondition(request.getCondition());
        try (final var qm = new QueryManager()) {
            final Long licenseId = resolveLicenseId(qm, request.getLicense());
            final long id = inJdbiTransaction(handle -> new ComponentPolicyDao(handle).create(
                    request.getName(), request.getDescription(), getPrincipal().getName(),
                    Objects.requireNonNullElse(request.getEnabled(), true),
                    Objects.requireNonNullElse(request.getPriority(), 0),
                    request.getCondition(), licenseId, request.getDetails(),
                    request.getValidFrom() != null ? request.getValidFrom().toInstant() : null,
                    request.getValidUntil() != null ? request.getValidUntil().toInstant() : null));
            return Response.created(uriInfo.getBaseUriBuilder()
                            .path("/component-policies")
                            .path(String.valueOf(id))
                            .build())
                    .build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response updateComponentPolicy(final Long id, final UpsertComponentPolicyRequest request) {
        validateCondition(request.getCondition());
        try (final var qm = new QueryManager()) {
            final Long licenseId = resolveLicenseId(qm, request.getLicense());
            final boolean updated = inJdbiTransaction(handle -> new ComponentPolicyDao(handle).update(
                    id, request.getName(), request.getDescription(),
                    Objects.requireNonNullElse(request.getEnabled(), true),
                    Objects.requireNonNullElse(request.getPriority(), 0),
                    request.getCondition(), licenseId, request.getDetails(),
                    request.getValidFrom() != null ? request.getValidFrom().toInstant() : null,
                    request.getValidUntil() != null ? request.getValidUntil().toInstant() : null));
            if (!updated) {
                throw new NotFoundException();
            }
            return Response.noContent().build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deleteComponentPolicy(final Long id) {
        final boolean deleted = inJdbiTransaction(
                handle -> new ComponentPolicyDao(handle).delete(id));
        if (!deleted) {
            throw new NotFoundException();
        }
        return Response.noContent().build();
    }

    private static void validateCondition(final String condition) {
        try {
            CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT)
                    .compile(condition, CelPolicyCompiler.CacheMode.NO_CACHE);
        } catch (CelValidationException e) {
            throw new BadRequestException("Invalid CEL condition: " + e.getMessage());
        }
    }

    private static Long resolveLicenseId(final QueryManager qm, final String licenseIdOrName) {
        if (licenseIdOrName == null) {
            return null;
        }
        final License license = qm.getLicenseByIdOrName(licenseIdOrName);
        if (license != null && license != License.UNRESOLVED) {
            return license.getId();
        }
        final License customLicense = qm.getCustomLicenseByName(licenseIdOrName);
        if (customLicense != null && customLicense != License.UNRESOLVED) {
            return customLicense.getId();
        }
        throw new BadRequestException("License %s is not known; create it as a custom license first".formatted(licenseIdOrName));
    }

    private static ComponentPolicy mapPolicy(final QueryManager qm, final ComponentPolicyDao.ComponentPolicy policy) {
        String license = null;
        if (policy.licenseId() != null) {
            final License resolved = qm.getObjectById(License.class, policy.licenseId());
            if (resolved != null) {
                license = resolved.getLicenseId() != null ? resolved.getLicenseId() : resolved.getName();
            }
        }
        return ComponentPolicy.builder()
                .id(policy.id())
                .name(policy.name())
                .description(policy.description())
                .author(policy.author())
                .enabled(policy.enabled())
                .priority(policy.priority())
                .condition(policy.condition())
                .license(license)
                .details(policy.details())
                .validFrom(policy.validFrom() != null
                        ? policy.validFrom().atOffset(java.time.ZoneOffset.UTC) : null)
                .validUntil(policy.validUntil() != null
                        ? policy.validUntil().atOffset(java.time.ZoneOffset.UTC) : null)
                .build();
    }
}
