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
import alpine.event.framework.Event;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permissions;
import org.owasp.dependencytrack.event.BomUploadEvent;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.resources.v1.vo.BomSubmitRequest;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Base64;

/**
 * JAX-RS resources for processing bill-of-material (bom) documents.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/bom")
@Api(value = "bom", authorizations = @Authorization(value = "X-Api-Key"))
public class BomResource extends AlpineResource {

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload a supported bil of material format document",
            notes = "Expects CycloneDX or SPDX (text or RDF) along and a valid project UUID. If a UUID is not specified, than the projectName and projectVersion must be specified. Optionally, if autoCreate is specified and 'true' and the project does not exist, the project will be created. In this scenario, the principal making the request will additionally need the PORTFOLIO_MANAGEMENT permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(BomSubmitRequest request) {
        final Validator validator = getValidator();
        if (request.getProject() != null) { // behavior in v3.0.0
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "bom")
            );
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                return process(project, request.getBom());
            }
        } else { // additional behavior added in v3.1.0
            failOnValidationError(
                    validator.validateProperty(request, "projectName"),
                    validator.validateProperty(request, "projectVersion"),
                    validator.validateProperty(request, "bom")
            );
            try (QueryManager qm = new QueryManager()) {
                Project project = qm.getProject(request.getProjectName(), request.getProjectVersion());
                if (project == null && request.isAutoCreate()) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT)) {
                        project = qm.createProject(request.getProjectName(), null, request.getProjectVersion(), null, null, null, true);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(project, request.getBom());
            }
        }
    }

    /**
     * Common logic that processes a BoM given a project and encoded payload.
     */
    private Response process(Project project, String encodedBomData) {
        if (project != null) {
            final byte[] decoded = Base64.getDecoder().decode(encodedBomData);
            Event.dispatch(new BomUploadEvent(project.getUuid(), decoded));
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

}
