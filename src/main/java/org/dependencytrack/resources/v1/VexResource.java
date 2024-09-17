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
package org.dependencytrack.resources.v1;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.CycloneDxMediaType;
import org.cyclonedx.exception.GeneratorException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.VexUploadEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.InvalidBomProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.VexSubmitRequest;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataParam;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * JAX-RS resources for processing VEX documents.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
@Path("/v1/vex")
@Tag(name = "vex")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class VexResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(VexResource.class);

    @GET
    @Path("/cyclonedx/project/{uuid}")
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON, MediaType.APPLICATION_OCTET_STREAM})
    @Operation(
            summary = "Returns a VEX for a project in CycloneDX format",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A VEX for a project in CycloneDX format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response exportProjectAsCycloneDx (
            @Parameter(description = "The UUID of the project to export", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Force the resulting VEX to be downloaded as a file (defaults to 'false')")
            @QueryParam("download") boolean download) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }

            final CycloneDXExporter exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VEX, qm);

            try {
                if (download) {
                    return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON), MediaType.APPLICATION_OCTET_STREAM)
                            .header("content-disposition","attachment; filename=\"" + project.getUuid() + "-vex.cdx.json\"").build();
                } else {
                    return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON),
                            CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                }
            } catch (GeneratorException e) {
                LOGGER.error("An error occurred while building a CycloneDX document for export", e);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Upload a supported VEX document",
            description = """
                    <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                    </p>
                    <p>
                      The VEX will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>
                      The maximum allowed length of the <code>vex</code> value is 20'000'000 characters.
                      When uploading large VEX files, the <code>POST</code> endpoint is preferred,
                      as it does not have this limit.
                    </p>
                    <p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking VEX processing progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid VEX",
                    content = @Content(
                            schema = @Schema(implementation = InvalidBomProblemDetails.class),
                            mediaType = ProblemDetails.MEDIA_TYPE_JSON
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response uploadVex(VexSubmitRequest request) {
        final Validator validator = getValidator();
        if (request.getProject() != null) {
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "vex")
            );
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                return process(qm, project, request.getVex());
            }
        } else {
            failOnValidationError(
                    validator.validateProperty(request, "projectName"),
                    validator.validateProperty(request, "projectVersion"),
                    validator.validateProperty(request, "vex")
            );
            try (QueryManager qm = new QueryManager()) {
                Project project = qm.getProject(request.getProjectName(), request.getProjectVersion());
                return process(qm, project, request.getVex());
            }
        }
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Upload a supported VEX document",
            description = """
                    <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                    </p>
                    <p>
                      The VEX will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking VEX processing progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid VEX",
                    content = @Content(
                            schema = @Schema(implementation = InvalidBomProblemDetails.class),
                            mediaType = ProblemDetails.MEDIA_TYPE_JSON
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response uploadVex(@FormDataParam("project") String projectUuid,
                              @FormDataParam("projectName") String projectName,
                              @FormDataParam("projectVersion") String projectVersion,
                              @Parameter(schema = @Schema(type = "string")) @FormDataParam("vex") final List<FormDataBodyPart> artifactParts) {
        if (projectUuid != null) {
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                return process(qm, project, artifactParts);
            }
        } else {
            try (QueryManager qm = new QueryManager()) {
                final String trimmedProjectName = StringUtils.trimToNull(projectName);
                final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);
                Project project = qm.getProject(trimmedProjectName, trimmedProjectVersion);
                return process(qm, project, artifactParts);
            }
        }
    }

    /**
     * Common logic that processes a VEX given a project and encoded payload.
     */
    private Response process(QueryManager qm, Project project, String encodedVexData) {
        if (project != null) {
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }
            final byte[] decoded = Base64.getDecoder().decode(encodedVexData);
            BomResource.validate(decoded, project);
            final VexUploadEvent vexUploadEvent = new VexUploadEvent(project.getUuid(), decoded);
            Event.dispatch(vexUploadEvent);
            return Response.ok(Collections.singletonMap("token", vexUploadEvent.getChainIdentifier())).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

    /**
     * Common logic that processes a VEX given a project and list of multi-party form objects containing decoded payloads.
     */
    private Response process(QueryManager qm, Project project, List<FormDataBodyPart> artifactParts) {
        for (final FormDataBodyPart artifactPart: artifactParts) {
            final BodyPartEntity bodyPartEntity = (BodyPartEntity) artifactPart.getEntity();
            if (project != null) {
                if (! qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                try (InputStream in = bodyPartEntity.getInputStream()) {
                    final byte[] content = IOUtils.toByteArray(BOMInputStream.builder().setInputStream(in).get());
                    BomResource.validate(content, project);
                    final VexUploadEvent vexUploadEvent = new VexUploadEvent(project.getUuid(), content);
                    Event.dispatch(vexUploadEvent);
                    return Response.ok(Collections.singletonMap("token", vexUploadEvent.getChainIdentifier())).build();
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
