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
import org.dependencytrack.api.v2.KevDataSourcesApi;
import org.dependencytrack.api.v2.model.KevDataSourceMirrorStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.kevdatasource.KevDataSourceMirrorService;
import org.dependencytrack.kevdatasource.KevDataSourceMirrorService.MirrorStatus;
import org.dependencytrack.kevdatasource.KevDataSourceMirrorService.TriggerResult;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.dependencytrack.resources.v2.exception.ProblemType;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

/// @since 5.1.0
@Provider
public final class KevDataSourcesResource extends AbstractApiResource implements KevDataSourcesApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(KevDataSourcesResource.class);

    private final KevDataSourceMirrorService mirrorService;

    @Inject
    KevDataSourcesResource(KevDataSourceMirrorService mirrorService) {
        this.mirrorService = mirrorService;
    }

    @Override
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_READ})
    public Response getLatestKevDataSourceMirrorRun(String name) {
        final MirrorStatus status = mirrorService.getLatestStatus(name);
        if (status == null) {
            throw new NotFoundException();
        }

        return Response.ok(KevDataSourceMirrorStatus.builder()
                        .status(convert(status.status()))
                        .startedAt(
                                status.startedAt() != null ? status.startedAt().toEpochMilli() : null)
                        .completedAt(
                                status.completedAt() != null
                                        ? status.completedAt().toEpochMilli()
                                        : null)
                        .failureReason(status.failureReason())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE})
    public Response triggerKevDataSourceMirrorRun(String name) {
        final TriggerResult result = mirrorService.trigger(name, getPrincipal().getName());

        return switch (result) {
            case TriggerResult.Triggered _ -> {
                LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Triggered KEV data source mirror for {}", name);
                yield Response.accepted()
                        .header(
                                "Location",
                                getUriInfo()
                                        .getBaseUriBuilder()
                                        .path("/kev-data-sources/{name}/mirror-runs/latest")
                                        .resolveTemplate("name", name)
                                        .build())
                        .build();
            }
            case TriggerResult.AlreadyRunning _ ->
                throw ProblemDetailsException.of(
                        ProblemType.KEV_DATA_SOURCE_MIRROR_ALREADY_RUNNING,
                        "A mirror run for this data source is already in progress");
            case TriggerResult.NotEnabled _ ->
                throw ProblemDetailsException.of(
                        ProblemType.KEV_DATA_SOURCE_NOT_ENABLED, "The KEV data source is not enabled");
            case TriggerResult.NotFound _ -> throw new NotFoundException();
        };
    }

    private static KevDataSourceMirrorStatus.StatusEnum convert(MirrorStatus.Status status) {
        return switch (status) {
            case PENDING -> KevDataSourceMirrorStatus.StatusEnum.PENDING;
            case RUNNING -> KevDataSourceMirrorStatus.StatusEnum.RUNNING;
            case COMPLETED -> KevDataSourceMirrorStatus.StatusEnum.COMPLETED;
            case FAILED -> KevDataSourceMirrorStatus.StatusEnum.FAILED;
        };
    }
}
