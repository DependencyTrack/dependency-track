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
package org.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.event.framework.Event;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.io.IOUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.ScanUploadEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.ScanSubmitRequest;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.FormDataParam;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

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
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project UUID. If a UUID is not specified, than the projectName and projectVersion must be specified. Optionally, if autoCreate is specified and 'true' and the project does not exist, the project will be created. In this scenario, the principal making the request will additionally need the PORTFOLIO_MANAGEMENT or PROJECT_CREATION_UPLOAD permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SCAN_UPLOAD)
    public Response uploadScan(ScanSubmitRequest request) {
        final Validator validator = getValidator();
        if (request.getProject() != null) { // behavior in v3.0.0
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "scan")
            );
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                return process(project, request.getScan());
            }
        } else { // additional behavior added in v3.1.0
            failOnValidationError(
                    validator.validateProperty(request, "projectName"),
                    validator.validateProperty(request, "projectVersion"),
                    validator.validateProperty(request, "scan")
            );
            try (QueryManager qm = new QueryManager()) {
                Project project = qm.getProject(request.getProjectName(), request.getProjectVersion());
                if (project == null && request.isAutoCreate()) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        project = qm.createProject(request.getProjectName(), null, request.getProjectVersion(), null, null, null, true);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(project, request.getScan());
            }
        }
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload Dependency-Check Result",
            notes = "Expects one or more dependency-check-report.xml schema version 1.3 or higher, and a valid project UUID. If a UUID is not specified, than the projectName and projectVersion must be specified. Optionally, if autoCreate is specified and 'true' and the project does not exist, the project will be created. In this scenario, the principal making the request will additionally need the PORTFOLIO_MANAGEMENT or PROJECT_CREATION_UPLOAD permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SCAN_UPLOAD)
    public Response uploadScan(@FormDataParam("project") String projectUuid,
                               @DefaultValue("false") @FormDataParam("autoCreate") boolean autoCreate,
                               @FormDataParam("projectName") String projectName,
                               @FormDataParam("projectVersion") String projectVersion,
                               final FormDataMultiPart multiPart) {

        final List<FormDataBodyPart> artifactParts = multiPart.getFields("scan");
        if (projectUuid != null) { // behavior in v3.0.0
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                return process(project, artifactParts);
            }
        } else { // additional behavior added in v3.1.0
            try (QueryManager qm = new QueryManager()) {
                Project project = qm.getProject(projectName, projectVersion);
                if (project == null && autoCreate) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        project = qm.createProject(projectName, null, projectVersion, null, null, null, true);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(project, artifactParts);
            }
        }
    }


    /**
     * Common logic that processes a scan given a project and encoded payload.
     */
    private Response process(Project project, String encodedScanData) {
        if (project != null) {
            final byte[] decodedScan = Base64.getDecoder().decode(encodedScanData);
            Event.dispatch(new ScanUploadEvent(project.getUuid(), decodedScan));
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

    /**
     * Common logic that processes a scan given a project and list of multi-party form objects containing decoded payloads.
     */
    private Response process(Project project, List<FormDataBodyPart> artifactParts) {
        for (FormDataBodyPart artifactPart: artifactParts) {
            BodyPartEntity bodyPartEntity = (BodyPartEntity) artifactPart.getEntity();
            if (project != null) {
                try {
                    final byte[] content = IOUtils.toByteArray(bodyPartEntity.getInputStream());
                    // todo: make option to combine all the scan data so components are reconciled in a single pass.
                    // todo: https://github.com/DependencyTrack/dependency-track/issues/130
                    Event.dispatch(new ScanUploadEvent(project.getUuid(), content));
                } catch (IOException e) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
        return Response.ok().build();
    }

}
