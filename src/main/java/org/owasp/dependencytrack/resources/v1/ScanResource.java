/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.event.framework.EventService;
import alpine.model.ApiKey;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permissions;
import org.owasp.dependencytrack.event.ScanUploadEvent;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.resources.v1.vo.ScanSubmitNameVersionRequest;
import org.owasp.dependencytrack.resources.v1.vo.ScanSubmitRequest;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Base64;

/**
 * JAX-RS resources for processing scans.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/scan")
@Api(value = "scan", authorizations = @Authorization(value = "X-Api-Key"))
public class ScanResource extends AlpineResource {

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project UUID"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SCAN_UPLOAD)
    public Response uploadScan(ScanSubmitRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "scan")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, request.getProject());
            return process(project, request.getScan());
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project name and project version. If autoCreate is true, the project with the corresponding name and version will automatically be created if it doesn't exist. This additionally requires PORTFOLIO_MANAGEMENT permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SCAN_UPLOAD)
    public Response uploadScan(ScanSubmitNameVersionRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "projectName"),
                validator.validateProperty(request, "projectVersion"),
                validator.validateProperty(request, "scan")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getProject(request.getProjectName(), request.getProjectVersion());
            if (project == null && request.isAutoCreate()) {
                boolean hasPermission = false;
                if (super.getPrincipal() instanceof UserPrincipal) {
                    hasPermission = qm.hasPermission((UserPrincipal)getPrincipal(), Permissions.Constants.PORTFOLIO_MANAGEMENT, true);
                } else if (super.getPrincipal() instanceof ApiKey) {
                    hasPermission = qm.hasPermission((ApiKey)getPrincipal(), Permissions.Constants.PORTFOLIO_MANAGEMENT);
                }
                if (hasPermission) {
                    qm.createProject(request.getProjectName(), null, request.getProjectVersion(), null, null, null, true);
                } else {
                    return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                }
            }
            return process(project, request.getScan());
        }
    }

    /**
     * Common logic that processes a scan given a project and encoded payload.
     */
    private Response process(Project project, String encodedScanData) {
        if (project != null) {
            final byte[] decodedScan = Base64.getDecoder().decode(encodedScanData);
            EventService.getInstance().publish(new ScanUploadEvent(project.getUuid(), decodedScan));
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

}
