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
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.CycloneDxMediaType;
import org.cyclonedx.exception.GeneratorException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.parser.cyclonedx.CycloneDxValidator;
import org.dependencytrack.parser.cyclonedx.InvalidBomException;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.InvalidBomProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.IsTokenBeingProcessedResponse;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataParam;

import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * JAX-RS resources for processing bill-of-material (bom) documents.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/bom")
@Api(value = "bom", authorizations = @Authorization(value = "X-Api-Key"))
public class BomResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(BomResource.class);

    @GET
    @Path("/cyclonedx/project/{uuid}")
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_XML, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON, MediaType.APPLICATION_OCTET_STREAM})
    @ApiOperation(
            value = "Returns dependency metadata for a project in CycloneDX format",
            response = String.class,
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportProjectAsCycloneDx (
            @ApiParam(value = "The UUID of the project to export", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @ApiParam(value = "The format to output (defaults to JSON)")
            @QueryParam("format") String format,
            @ApiParam(value = "Specifies the CycloneDX variant to export. Value options are 'inventory' and 'withVulnerabilities'. (defaults to 'inventory')")
            @QueryParam("variant") String variant,
            @ApiParam(value = "Force the resulting BOM to be downloaded as a file (defaults to 'false')")
            @QueryParam("download") boolean download) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }

            final CycloneDXExporter exporter;
            if (StringUtils.trimToNull(variant) == null || variant.equalsIgnoreCase("inventory")) {
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY, qm);
            } else if (variant.equalsIgnoreCase("withVulnerabilities")) {
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY_WITH_VULNERABILITIES, qm);
            } else if (variant.equalsIgnoreCase("vdr")) {
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VDR, qm);
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM variant specified.").build();
            }

            try {
                if (StringUtils.trimToNull(format) == null || format.equalsIgnoreCase("JSON")) {
                    if (download) {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON), MediaType.APPLICATION_OCTET_STREAM)
                                .header("content-disposition","attachment; filename=\"" + project.getUuid() + "-" + variant + ".cdx.json\"").build();
                    } else {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON),
                                CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                    }
                } else if (format.equalsIgnoreCase("XML")) {
                    if (download) {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.XML), MediaType.APPLICATION_OCTET_STREAM)
                                .header("content-disposition","attachment; filename=\"" + project.getUuid() + "-" + variant + ".cdx.xml\"").build();
                    } else {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.XML),
                                CycloneDxMediaType.APPLICATION_CYCLONEDX_XML).build();
                    }
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM format specified.").build();
                }
            } catch (GeneratorException e) {
                LOGGER.error("An error occurred while building a CycloneDX document for export", e);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        }
    }

    @GET
    @Path("/cyclonedx/component/{uuid}")
    @Produces(CycloneDxMediaType.APPLICATION_CYCLONEDX_XML)
    @ApiOperation(
            value = "Returns dependency metadata for a specific component in CycloneDX format",
            response = String.class,
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified component is forbidden"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportComponentAsCycloneDx (
            @ApiParam(value = "The UUID of the component to export", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @ApiParam(value = "The format to output (defaults to JSON)")
            @QueryParam("format") String format) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            if (! qm.hasAccess(super.getPrincipal(), component.getProject())) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
            }

            final CycloneDXExporter exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY, qm);
            try {
                if (StringUtils.trimToNull(format) == null || format.equalsIgnoreCase("JSON")) {
                    return Response.ok(exporter.export(exporter.create(component), CycloneDXExporter.Format.JSON),
                            CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                } else if (format.equalsIgnoreCase("XML")) {
                    return Response.ok(exporter.export(exporter.create(component), CycloneDXExporter.Format.XML),
                            CycloneDxMediaType.APPLICATION_CYCLONEDX_XML).build();
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM format specified.").build();
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
    @ApiOperation(
            value = "Upload a supported bill of material format document",
            notes = """
                    <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                      Optionally, if <code>autoCreate</code> is specified and <code>true</code> and the project does not exist,
                      the project will be created. In this scenario, the principal making the request will
                      additionally need the <strong>PORTFOLIO_MANAGEMENT</strong> or
                      <strong>PROJECT_CREATION_UPLOAD</strong> permission.
                    </p>
                    <p>
                      The BOM will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>
                      The maximum allowed length of the <code>bom</code> value is 20'000'000 characters.
                      When uploading large BOMs, the <code>POST</code> endpoint is preferred,
                      as it does not have this limit.
                    </p>
                    <p>Requires permission <strong>BOM_UPLOAD</strong></p>""",
            response = BomUploadResponse.class,
            nickname = "UploadBomBase64Encoded"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Invalid BOM", response = InvalidBomProblemDetails.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(@ApiParam(required = true) BomSubmitRequest request) {
        final Validator validator = getValidator();
        if (request.getProject() != null) { // behavior in v3.0.0
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "bom")
            );
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                return process(qm, project, request.getBom());
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
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        Project parent = null;
                        if (request.getParentUUID() != null || request.getParentName() != null) {
                            if (request.getParentUUID() != null) {
                                failOnValidationError(validator.validateProperty(request, "parentUUID"));
                                parent = qm.getObjectByUuid(Project.class, request.getParentUUID());
                            } else {
                                failOnValidationError(
                                        validator.validateProperty(request, "parentName"),
                                        validator.validateProperty(request, "parentVersion")
                                );
                                final String trimmedParentName = StringUtils.trimToNull(request.getParentName());
                                final String trimmedParentVersion = StringUtils.trimToNull(request.getParentVersion());
                                parent = qm.getProject(trimmedParentName, trimmedParentVersion);
                            }

                            if (parent == null) { // if parent project is specified but not found
                                return Response.status(Response.Status.NOT_FOUND).entity("The parent component could not be found.").build();
                            } else if (! qm.hasAccess(super.getPrincipal(), parent)) {
                                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified parent project is forbidden").build();
                            }
                        }

                        project = qm.createProject(StringUtils.trimToNull(request.getProjectName()), null, StringUtils.trimToNull(request.getProjectVersion()), null, parent, null, true, true);
                        Principal principal = getPrincipal();
                        qm.updateNewProjectACL(project, principal);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(qm, project, request.getBom());
            }
        }
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload a supported bill of material format document",
            notes = """
                   <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                      Optionally, if <code>autoCreate</code> is specified and <code>true</code> and the project does not exist,
                      the project will be created. In this scenario, the principal making the request will
                      additionally need the <strong>PORTFOLIO_MANAGEMENT</strong> or
                      <strong>PROJECT_CREATION_UPLOAD</strong> permission.
                    </p>
                    <p>
                      The BOM will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>Requires permission <strong>BOM_UPLOAD</strong></p>""",
            response = BomUploadResponse.class,
            nickname = "UploadBom"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Invalid BOM", response = InvalidBomProblemDetails.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(@FormDataParam("project") String projectUuid,
                               @DefaultValue("false") @FormDataParam("autoCreate") boolean autoCreate,
                               @FormDataParam("projectName") String projectName,
                               @FormDataParam("projectVersion") String projectVersion,
                               @FormDataParam("parentName") String parentName,
                               @FormDataParam("parentVersion") String parentVersion,
                               @FormDataParam("parentUUID") String parentUUID,
                               @ApiParam(type = "string") @FormDataParam("bom") final List<FormDataBodyPart> artifactParts) {
        if (projectUuid != null) { // behavior in v3.0.0
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                return process(qm, project, artifactParts);
            }
        } else { // additional behavior added in v3.1.0
            try (QueryManager qm = new QueryManager()) {
                final String trimmedProjectName = StringUtils.trimToNull(projectName);
                final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);
                Project project = qm.getProject(trimmedProjectName, trimmedProjectVersion);
                if (project == null && autoCreate) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        Project parent = null;
                        if (parentUUID != null || parentName != null) {
                            if (parentUUID != null) {

                              parent = qm.getObjectByUuid(Project.class, parentUUID);
                            } else {
                              final String trimmedParentName = StringUtils.trimToNull(parentName);
                              final String trimmedParentVersion = StringUtils.trimToNull(parentVersion);
                              parent = qm.getProject(trimmedParentName, trimmedParentVersion);
                            }

                            if (parent == null) { // if parent project is specified but not found
                                return Response.status(Response.Status.NOT_FOUND).entity("The parent component could not be found.").build();
                            } else if (! qm.hasAccess(super.getPrincipal(), parent)) {
                                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified parent project is forbidden").build();
                            }
                        }
                        project = qm.createProject(trimmedProjectName, null, trimmedProjectVersion, null, parent, null, true, true);
                        Principal principal = getPrincipal();
                        qm.updateNewProjectACL(project, principal);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(qm, project, artifactParts);
            }
        }
    }

    @GET
    @Path("/token/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.",
            notes = """
                    <p>
                      This endpoint is intended to be used in conjunction with uploading a supported BOM document.
                      Upon upload, a token will be returned. The token can then be queried using this endpoint to
                      determine if any tasks (such as vulnerability analysis) is being performed on the BOM:
                      <ul>
                        <li>A value of <code>true</code> indicates processing is occurring.</li>
                        <li>A value of <code>false</code> indicates that no processing is occurring for the specified token.</li>
                      </ul>
                      However, a value of <code>false</code> also does not confirm the token is valid,
                      only that no processing is associated with the specified token.
                    </p>
                    <p>Requires permission <strong>BOM_UPLOAD</strong></p>
                    <p><strong>Deprecated</strong>. Use <code>/v1/event/token/{uuid}</code> instead.</p>""",
            response = IsTokenBeingProcessedResponse.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    @Deprecated(since = "4.11.0")
    public Response isTokenBeingProcessed (
            @ApiParam(value = "The UUID of the token to query", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid) {

        final boolean value = Event.isEventBeingProcessed(UUID.fromString(uuid));

        IsTokenBeingProcessedResponse response = new IsTokenBeingProcessedResponse();

        response.setProcessing(value);

        return Response.ok(response).build();
    }

    /**
     * Common logic that processes a BOM given a project and encoded payload.
     */
    private Response process(QueryManager qm, Project project, String encodedBomData) {
        if (project != null) {
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }
            if(!project.getCollectionLogic().equals(ProjectCollectionLogic.NONE)) {
                return Response.status(Response.Status.BAD_REQUEST).entity("BOM cannot be uploaded to collection project.").build();
            }
            final byte[] decoded = Base64.getDecoder().decode(encodedBomData);
            try (final ByteArrayInputStream bain = new ByteArrayInputStream(decoded)) {
                final byte[] content = IOUtils.toByteArray(new BOMInputStream((bain)));
                validate(content);
                final BomUploadEvent bomUploadEvent = new BomUploadEvent(qm.getPersistenceManager().detachCopy(project), content);
                Event.dispatch(bomUploadEvent);
                return Response.ok(Collections.singletonMap("token", bomUploadEvent.getChainIdentifier())).build();
            } catch (IOException e) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            }
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

    /**
     * Common logic that processes a BOM given a project and list of multi-party form objects containing decoded payloads.
     */
    private Response process(QueryManager qm, Project project, List<FormDataBodyPart> artifactParts) {
        for (final FormDataBodyPart artifactPart: artifactParts) {
            final BodyPartEntity bodyPartEntity = (BodyPartEntity) artifactPart.getEntity();
            if (project != null) {
                if (! qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                if(!project.getCollectionLogic().equals(ProjectCollectionLogic.NONE)) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("BOM cannot be uploaded to collection project.").build();
                }
                try (InputStream in = bodyPartEntity.getInputStream()) {
                    final byte[] content = IOUtils.toByteArray(new BOMInputStream((in)));
                    validate(content);
                    // todo: make option to combine all the bom data so components are reconciled in a single pass.
                    // todo: https://github.com/DependencyTrack/dependency-track/issues/130
                    final BomUploadEvent bomUploadEvent = new BomUploadEvent(qm.getPersistenceManager().detachCopy(project), content);
                    Event.dispatch(bomUploadEvent);

                    BomUploadResponse bomUploadResponse = new BomUploadResponse();

                    bomUploadResponse.setToken(bomUploadEvent.getChainIdentifier());

                    return Response.ok(bomUploadResponse).build();
                } catch (IOException e) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
        return Response.ok().build();
    }

    static void validate(final byte[] bomBytes) {
        try (QueryManager qm = new QueryManager()) {
            if (!qm.isEnabled(ConfigPropertyConstants.BOM_VALIDATION_ENABLED)) {
                return;
            }
        }

        try {
            CycloneDxValidator.getInstance().validate(bomBytes);
        } catch (InvalidBomException e) {
            final var problemDetails = new InvalidBomProblemDetails();
            problemDetails.setStatus(400);
            problemDetails.setTitle("The uploaded BOM is invalid");
            problemDetails.setDetail(e.getMessage());
            if (!e.getValidationErrors().isEmpty()) {
                problemDetails.setErrors(e.getValidationErrors());
            }

            final Response response = Response.status(Response.Status.BAD_REQUEST)
                    .header("Content-Type", ProblemDetails.MEDIA_TYPE_JSON)
                    .entity(problemDetails)
                    .build();

            throw new WebApplicationException(response);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to validate BOM", e);
            final Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            throw new WebApplicationException(response);
        }
    }

}
