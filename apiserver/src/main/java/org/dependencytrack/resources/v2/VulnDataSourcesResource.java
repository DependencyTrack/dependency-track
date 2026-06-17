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
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.VulnDataSourcesApi;
import org.dependencytrack.api.v2.model.VulnDataSourceMirrorStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.dependencytrack.resources.v2.exception.ProblemType;
import org.dependencytrack.vulndatasource.VulnDataSourceMirrorService;
import org.dependencytrack.vulndatasource.VulnDataSourceMirrorService.MirrorStatus;
import org.dependencytrack.vulndatasource.VulnDataSourceMirrorService.TriggerResult;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @since 5.0.0
 */
@Provider
public final class VulnDataSourcesResource extends AbstractApiResource implements VulnDataSourcesApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDataSourcesResource.class);

    private final VulnDataSourceMirrorService mirrorService;

    @Inject
    VulnDataSourcesResource(VulnDataSourceMirrorService mirrorService) {
        this.mirrorService = mirrorService;
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getLatestVulnDataSourceMirrorRun(String name) {
        final MirrorStatus status = mirrorService.getLatestStatus(name);
        if (status == null) {
            throw new NotFoundException();
        }

        return Response
                .ok(VulnDataSourceMirrorStatus.builder()
                        .status(convert(status.status()))
                        .startedAt(status.startedAt() != null
                                ? status.startedAt().toEpochMilli()
                                : null)
                        .completedAt(status.completedAt() != null
                                ? status.completedAt().toEpochMilli()
                                : null)
                        .failureReason(status.failureReason())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response triggerVulnDataSourceMirrorRun(String name) {
        final TriggerResult result = mirrorService.trigger(name, getPrincipal().getName());

        return switch (result) {
            case TriggerResult.Triggered _ -> {
                LOGGER.info(
                        SecurityMarkers.SECURITY_AUDIT,
                        "Triggered vulnerability data source mirror for {}",
                        name);
                yield Response
                        .accepted()
                        .header("Location", getUriInfo()
                                .getBaseUriBuilder()
                                .path("/vuln-data-sources/{name}/mirror-runs/latest")
                                .resolveTemplate("name", name)
                                .build())
                        .build();
            }
            case TriggerResult.AlreadyRunning _ -> throw ProblemDetailsException.of(
                    ProblemType.VULN_DATA_SOURCE_MIRROR_ALREADY_RUNNING,
                    "A mirror run for this data source is already in progress");
            case TriggerResult.NotEnabled _ -> throw ProblemDetailsException.of(
                    ProblemType.VULN_DATA_SOURCE_NOT_ENABLED,
                    "The vulnerability data source is not enabled");
            case TriggerResult.NotFound _ -> throw new NotFoundException();
        };
    }

    private static VulnDataSourceMirrorStatus.StatusEnum convert(MirrorStatus.Status status) {
        return switch (status) {
            case PENDING -> VulnDataSourceMirrorStatus.StatusEnum.PENDING;
            case RUNNING -> VulnDataSourceMirrorStatus.StatusEnum.RUNNING;
            case COMPLETED -> VulnDataSourceMirrorStatus.StatusEnum.COMPLETED;
            case FAILED -> VulnDataSourceMirrorStatus.StatusEnum.FAILED;
        };
    }

}
