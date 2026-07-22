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
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ComponentAnalysesApi;
import org.dependencytrack.api.v2.model.ComponentAnalysisComment;
import org.dependencytrack.api.v2.model.CreateComponentAnalysisCommentRequest;
import org.dependencytrack.api.v2.model.ListComponentAnalysesResponse;
import org.dependencytrack.api.v2.model.ListComponentAnalysisCommentsResponse;
import org.dependencytrack.api.v2.model.UpsertComponentAnalysisRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.ComponentAnalysis;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.CreateCommentCommand;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * REST resource for component analyses (durable license curation).
 */
@Provider
public final class ComponentAnalysesResource extends AbstractApiResource implements ComponentAnalysesApi {

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponentAnalyses(final UUID project) {
        final long projectId = requireProjectId(project);
        final List<ComponentAnalysis> analyses = withJdbiHandle(
                handle -> new ComponentAnalysisDao(handle).getAllByProject(projectId));
        final var items = new ArrayList<org.dependencytrack.api.v2.model.ComponentAnalysis>(analyses.size());
        try (final var qm = new QueryManager()) {
            for (final ComponentAnalysis analysis : analyses) {
                items.add(mapAnalysis(qm, analysis));
            }
        }
        return Response.ok(ListComponentAnalysesResponse.builder().analyses(items).build()).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response updateComponentAnalysis(final UpsertComponentAnalysisRequest request) {
        final long projectId = requireProjectId(request.getProjectUuid());

        try (final var qm = new QueryManager()) {
            final Long licenseId;
            if (request.getLicense() != null) {
                licenseId = resolveLicense(qm, request.getLicense()).getId();
            } else {
                licenseId = null;
            }

            final String commenter = getPrincipal().getName();
            inJdbiTransaction(handle -> {
                final var dao = new ComponentAnalysisDao(handle);
                final ComponentAnalysis existing = dao.getByIdentity(
                        projectId, request.getPurl(), request.getGroup(),
                        request.getName(), request.getVersion()).orElse(null);
                final long id = dao.upsert(
                        projectId, request.getPurl(), request.getGroup(),
                        request.getName(), request.getVersion(),
                        licenseId, request.getDetails());
                final var comments = new ArrayList<CreateCommentCommand>();
                final Long oldLicenseId = existing != null ? existing.licenseId() : null;
                if (!Objects.equals(oldLicenseId, licenseId)) {
                    comments.add(new CreateCommentCommand(id, commenter,
                            "License override: %s → %s".formatted(
                                    oldLicenseId != null ? licenseLabel(qm, oldLicenseId) : "not set",
                                    request.getLicense() != null ? request.getLicense() : "not set")));
                }
                final String oldDetails = existing != null ? existing.details() : null;
                if (!Objects.equals(oldDetails, request.getDetails())) {
                    comments.add(new CreateCommentCommand(id, commenter,
                            "Details: %s → %s".formatted(
                                    Objects.requireNonNullElse(oldDetails, "not set"),
                                    Objects.requireNonNullElse(request.getDetails(), "not set"))));
                }
                if (!comments.isEmpty()) {
                    dao.createComments(comments);
                }
                if (licenseId != null) {
                    // first override on this component: snapshot the uploaded
                    // license so clearing can restore it instantly
                    if (existing == null || existing.licenseId() == null) {
                        dao.getComponentLicense(
                                projectId, request.getPurl(), request.getGroup(),
                                request.getName(), request.getVersion())
                            .ifPresent(row -> dao.updateDeclaredSnapshot(
                                    id, row.licenseId(), row.licenseName(),
                                    row.licenseExpression()));
                    }
                    dao.applyToComponents(
                            projectId, request.getPurl(), request.getGroup(),
                            request.getName(), request.getVersion(),
                            licenseId, request.getDetails());
                } else {
                    if (existing != null && existing.licenseId() != null) {
                        dao.restoreDeclaredLicense(
                                projectId, request.getPurl(), request.getGroup(),
                                request.getName(), request.getVersion(),
                                existing.declaredLicenseId(),
                                existing.declaredLicenseName(),
                                existing.declaredLicenseExpression());
                    }
                    dao.applyToComponents(
                            projectId, request.getPurl(), request.getGroup(),
                            request.getName(), request.getVersion(),
                            /* licenseId */ null, request.getDetails());
                }
                return null;
            });
            return Response.noContent().build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deleteComponentAnalysis(final Long id) {
        final boolean deleted = inJdbiTransaction(
                handle -> new ComponentAnalysisDao(handle).delete(id));
        if (!deleted) {
            throw new NotFoundException();
        }
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponentAnalysisComments(final Long id) {
        final List<ComponentAnalysisDao.ComponentAnalysisComment> comments = withJdbiHandle(
                handle -> new ComponentAnalysisDao(handle).getComments(id));
        return Response.ok(ListComponentAnalysisCommentsResponse.builder()
                .comments(comments.stream()
                        .<ComponentAnalysisComment>map(comment -> ComponentAnalysisComment.builder()
                                .timestamp(comment.timestamp().toEpochMilli())
                                .commenter(comment.commenter())
                                .comment(comment.comment())
                                .build())
                        .toList())
                .build()).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createComponentAnalysisComment(final Long id, final CreateComponentAnalysisCommentRequest request) {
        final String commenter = getPrincipal().getName();
        inJdbiTransaction(handle -> new ComponentAnalysisDao(handle)
                .createComments(List.of(new CreateCommentCommand(id, commenter, request.getComment()))));
        return Response.created(uriInfo.getBaseUriBuilder()
                        .path("/component-analyses")
                        .path(String.valueOf(id))
                        .path("/comments")
                        .build())
                .build();
    }

    private static long requireProjectId(final UUID uuid) {
        final Long projectId = withJdbiHandle(handle -> handle
                .createQuery("SELECT \"ID\" FROM \"PROJECT\" WHERE \"UUID\" = :uuid")
                .bind("uuid", uuid)
                .mapTo(Long.class)
                .findOne()
                .orElse(null));
        if (projectId == null) {
            throw new NotFoundException();
        }
        return projectId;
    }

    /**
     * Resolves an SPDX license ID or (custom) license name; 400 when unknown —
     * overrides must reference licenses DT can attach to components.
     */
    private static License resolveLicense(final QueryManager qm, final String licenseIdOrName) {
        final License license = qm.getLicenseByIdOrName(licenseIdOrName);
        if (license != null && license != License.UNRESOLVED) {
            return license;
        }
        final License customLicense = qm.getCustomLicenseByName(licenseIdOrName);
        if (customLicense != null && customLicense != License.UNRESOLVED) {
            return customLicense;
        }
        throw new BadRequestException("License %s is not known; create it as a custom license first".formatted(licenseIdOrName));
    }

    /**
     * Display label of a license: its SPDX ID, or the name for custom licenses.
     */
    private static String licenseLabel(final QueryManager qm, final long licenseId) {
        final License license = qm.getObjectById(License.class, licenseId);
        if (license == null) {
            return "unknown";
        }
        return license.getLicenseId() != null ? license.getLicenseId() : license.getName();
    }

    private static org.dependencytrack.api.v2.model.ComponentAnalysis mapAnalysis(
            final QueryManager qm, final ComponentAnalysis analysis) {
        final String licenseIdOrName = analysis.licenseId() != null
                ? licenseLabel(qm, analysis.licenseId())
                : null;
        String declaredLicense = analysis.declaredLicenseExpression();
        if (declaredLicense == null && analysis.declaredLicenseId() != null) {
            declaredLicense = licenseLabel(qm, analysis.declaredLicenseId());
        }
        if (declaredLicense == null) {
            declaredLicense = analysis.declaredLicenseName();
        }
        return org.dependencytrack.api.v2.model.ComponentAnalysis.builder()
                .id(analysis.id())
                .purl(analysis.purl())
                .group(analysis.group())
                .name(analysis.name())
                .version(analysis.version())
                .license(licenseIdOrName)
                .declaredLicense(declaredLicense)
                .details(analysis.details())
                .build();
    }
}
