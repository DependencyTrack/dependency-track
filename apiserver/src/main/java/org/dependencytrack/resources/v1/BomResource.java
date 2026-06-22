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

import alpine.model.ConfigProperty;
import alpine.server.auth.PermissionRequired;
import com.fasterxml.uuid.Generators;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.CycloneDxMediaType;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.ProjectAccess;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.parser.cyclonedx.CycloneDxValidator;
import org.dependencytrack.parser.cyclonedx.InvalidBomException;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.InvalidBomProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.IsTokenBeingProcessedResponse;
import org.dependencytrack.tasks.ImportBomWorkflow;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.function.Predicate.not;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE;
import static org.dependencytrack.notification.api.NotificationFactory.createBomValidationFailedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectCreatedNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/**
 * JAX-RS resources for processing bill-of-material (bom) documents.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/bom")
@io.swagger.v3.oas.annotations.tags.Tag(name = "bom")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class BomResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(BomResource.class);
    private static final String DEFAULT_EXPORT_VERSION = "1.5";

    @Inject
    private DexEngine dexEngine;

    @Inject
    private FileStorage fileStorage;

    @GET
    @Path("/cyclonedx/project/{uuid}")
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_XML, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON, MediaType.APPLICATION_OCTET_STREAM})
    @Operation(
            summary = "Returns dependency metadata for a project in CycloneDX format",
            description = """
                    <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>
                    <p>
                      The <code>withVulnerabilities</code> and <code>vdr</code> variants
                      further require any of the following permissions:
                      <ul>
                        <li><strong>VIEW_VULNERABILITY</strong></li>
                        <li><strong>VULNERABILITY_ANALYSIS</strong></li>
                        <li><strong>VULNERABILITY_ANALYSIS_READ</strong></li>
                      </ul>
                    </p>
                    """
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Dependency metadata for a project in CycloneDX format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportProjectAsCycloneDx(
            @Parameter(description = "The UUID of the project to export", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The format to output (defaults to JSON)")
            @QueryParam("format") String format,
            @Parameter(description = "Specifies the CycloneDX variant to export. Value options are 'inventory' and 'withVulnerabilities'. (defaults to 'inventory')")
            @QueryParam("variant") String variant,
            @Parameter(description = "Force the resulting BOM to be downloaded as a file (defaults to 'false')")
            @QueryParam("download") boolean download,
            @Parameter(description = "The CycloneDX Spec variant exported (defaults to: '" + DEFAULT_EXPORT_VERSION + "')")
            @QueryParam("version") String version
    ) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            String versionParameter = Objects.toString(StringUtils.trimToNull(version), DEFAULT_EXPORT_VERSION);
            Version cdxOutputVersion = Version.fromVersionString(versionParameter);
            if (cdxOutputVersion == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM version specified.").build();
            }

            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);

            final CycloneDXExporter exporter;
            if (StringUtils.trimToNull(variant) == null || variant.equalsIgnoreCase("inventory")) {
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY, qm);
            } else if (variant.equalsIgnoreCase("withVulnerabilities")) {
                if (Collections.disjoint(super.getEffectivePermissions(), Set.of(
                        Permissions.Constants.VIEW_VULNERABILITY,
                        Permissions.Constants.VULNERABILITY_ANALYSIS,
                        Permissions.Constants.VULNERABILITY_ANALYSIS_READ))) {
                    throw new ForbiddenException();
                }
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY_WITH_VULNERABILITIES, qm);
            } else if (variant.equalsIgnoreCase("vdr")) {
                if (Collections.disjoint(super.getEffectivePermissions(), Set.of(
                        Permissions.Constants.VIEW_VULNERABILITY,
                        Permissions.Constants.VULNERABILITY_ANALYSIS,
                        Permissions.Constants.VULNERABILITY_ANALYSIS_READ))) {
                    throw new ForbiddenException();
                }
                exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VDR, qm);
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM variant specified.").build();
            }

            try {
                if (StringUtils.trimToNull(format) == null || format.equalsIgnoreCase("JSON")) {
                    if (download) {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON, cdxOutputVersion), MediaType.APPLICATION_OCTET_STREAM)
                                .header("content-disposition", "attachment; filename=\"" + project.getUuid() + "-" + variant + ".cdx.json\"").build();
                    } else {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON, cdxOutputVersion),
                                CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                    }
                } else if (format.equalsIgnoreCase("XML")) {
                    if (download) {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.XML, cdxOutputVersion), MediaType.APPLICATION_OCTET_STREAM)
                                .header("content-disposition", "attachment; filename=\"" + project.getUuid() + "-" + variant + ".cdx.xml\"").build();
                    } else {
                        return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.XML, cdxOutputVersion),
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
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_XML, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON})
    @Operation(
            summary = "Returns dependency metadata for a specific component in CycloneDX format",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Dependency metadata for a specific component in CycloneDX format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportComponentAsCycloneDx(
            @Parameter(description = "The UUID of the component to export", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The format to output (defaults to JSON)")
            @QueryParam("format") String format,
            @Parameter(description = "The CycloneDX Spec variant exported (defaults to: '" + DEFAULT_EXPORT_VERSION + "')")
            @QueryParam("version") String version
    ) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            String versionParameter = Objects.toString(StringUtils.trimToNull(version), DEFAULT_EXPORT_VERSION);
            Version cdxOutputVersion = Version.fromVersionString(versionParameter);
            if (cdxOutputVersion == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM version specified.").build();
            }

            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            requireAccess(qm, component.getProject());

            final CycloneDXExporter exporter = new CycloneDXExporter(CycloneDXExporter.Variant.INVENTORY, qm);
            try {
                if (StringUtils.trimToNull(format) == null || format.equalsIgnoreCase("JSON")) {
                    return Response.ok(exporter.export(exporter.create(component), CycloneDXExporter.Format.JSON, cdxOutputVersion),
                            CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                } else if (format.equalsIgnoreCase("XML")) {
                    return Response.ok(exporter.export(exporter.create(component), CycloneDXExporter.Format.XML, cdxOutputVersion),
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
    @Operation(
            summary = "Upload a supported bill of material format document",
            description = """
                    <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                      Optionally, if <code>autoCreate</code> is specified and <code>true</code> and the project does not exist,
                      the project will be created. In this scenario, the principal making the request will
                      additionally need the <strong>PORTFOLIO_MANAGEMENT</strong>, <strong>PORTFOLIO_MANAGEMENT_CREATE</strong>,
                      or <strong>PROJECT_CREATION_UPLOAD</strong> permission.
                    </p>
                    <p>
                      The BOM will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>
                      The upload can target an existing project directly with <code>project</code>, or use
                      <code>projectName</code> and <code>projectVersion</code> to look up the project and,
                      with <code>autoCreate</code>, create it when it does not already exist. When creating
                      projects, <code>parentUUID</code> or <code>parentName</code> and
                      <code>parentVersion</code> can place the new project under a parent,
                      <code>projectTags</code> can apply tags, and <code>isLatest</code> can mark it as
                      the latest version. The <code>isActive</code> parameter sets the project's active
                      state whenever it is provided, including when the target project already exists, so
                      clients should send it only when they intend to change that state.
                    </p>
                    <p>
                      The maximum allowed length of the <code>bom</code> value is 20'000'000 characters.
                      When uploading large BOMs, the <code>POST</code> endpoint is preferred,
                      as it does not have this limit.
                    </p>
                    <p>Requires permission <strong>BOM_UPLOAD</strong></p>""",
            operationId = "UploadBomBase64Encoded"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking BOM processing progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid BOM",
                    content = @Content(
                            schema = @Schema(implementation = InvalidBomProblemDetails.class),
                            mediaType = ProblemDetails.MEDIA_TYPE_JSON
                    )
            ),
            @ApiResponse(responseCode = "400", description = "The uploaded BOM is invalid"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(@Parameter(required = true) BomSubmitRequest request) {
        final Validator validator = getValidator();
        final ProjectInfo projectInfo;
        if (request.getProject() != null) { // behavior in v3.0.0
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "bom")
            );
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                projectInfo = qm.callInTransaction(() -> {
                    final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                    if (project == null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The project could not be found.")
                                .build());
                    }
                    requireAccess(qm, project);
                    if (project.getCollectionLogic() != null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("BOM cannot be uploaded to a collection project.")
                                .build());
                    }
                    maybeBindTags(qm, project, request.getProjectTags());
                    if (request.isActive() != null) {
                        project.setActive(request.isActive());
                    }
                    return ProjectInfo.of(project);
                });
            }
        } else { // additional behavior added in v3.1.0
            failOnValidationError(
                    validator.validateProperty(request, "projectName"),
                    validator.validateProperty(request, "projectVersion"),
                    validator.validateProperty(request, "bom")
            );
            try (final var qm = new QueryManager(getAlpineRequest())) {
                projectInfo = qm.callInTransaction(() -> {
                    final String trimmedProjectName = StringUtils.trimToNull(request.getProjectName());
                    final String trimmedProjectVersion = StringUtils.trimToNull(request.getProjectVersion());

                    // NB: Bypass portfolio ACL for this lookup since it would otherwise filter out existing
                    // projects that are inaccessible. `autoCreate=true` would then lead to us trying to create
                    // a project that already exists, triggering a unique constraint violation.
                    // Access to the project (and potentially its parent) is asserted explicitly via requireAccess().
                    Project project = ProjectAccess.unrestricted(
                            () -> qm.getProject(trimmedProjectName, trimmedProjectVersion));

                    if (project == null && request.isAutoCreate()) {
                        if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
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
                                    parent = ProjectAccess.unrestricted(() -> qm.getProject(trimmedParentName, trimmedParentVersion));
                                }

                                if (parent == null) {
                                    throw new WebApplicationException(Response
                                            .status(Response.Status.NOT_FOUND)
                                            .entity("The parent project could not be found.")
                                            .build());
                                }
                                requireAccess(qm, parent, "Access to the specified parent project is forbidden");
                            }
                            if (request.isLatest()) {
                                final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(trimmedProjectName));
                                if (oldLatest != null) {
                                    requireAccess(qm, oldLatest, "Access to the previous latest project version is forbidden");
                                }
                            }
                            try {
                                project = qm.createProject(trimmedProjectName, null,
                                        trimmedProjectVersion, request.getProjectTags(), parent, null,
                                        Boolean.FALSE.equals(request.isActive()) ? Date.from(Instant.now()) : null,
                                        request.isLatest(), true);
                            } catch (RuntimeException e) {
                                if (isUniqueConstraintViolation(e)) {
                                    throw new WebApplicationException(Response
                                            .status(Response.Status.CONFLICT)
                                            .entity("A project with the specified name and version already exists.")
                                            .build());
                                }
                                throw e;
                            }
                            Principal principal = getPrincipal();
                            qm.updateNewProjectACL(project, principal);
                            new JdoNotificationEmitter(qm).emit(
                                    createProjectCreatedNotification(
                                            NotificationModelConverter.convert(project)));
                        } else {
                            throw new WebApplicationException(Response
                                    .status(Response.Status.UNAUTHORIZED)
                                    .entity("The principal does not have permission to create project.")
                                    .build());
                        }
                    }

                    if (project == null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The project could not be found.")
                                .build());
                    }
                    requireAccess(qm, project);
                    if (project.getCollectionLogic() != null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("BOM cannot be uploaded to a collection project.")
                                .build());
                    }
                    maybeBindTags(qm, project, request.getProjectTags());
                    if (request.isActive() != null) {
                        project.setActive(request.isActive());
                    }
                    return ProjectInfo.of(project);
                });
            }
        }

        final byte[] bomBytes;
        try (final var encodedInputStream = new ByteArrayInputStream(request.getBom().getBytes(StandardCharsets.UTF_8));
             final var decodedInputStream = Base64.getDecoder().wrap(encodedInputStream);
             final var byteOrderMarkInputStream = BOMInputStream.builder().setInputStream(decodedInputStream).get()) {
            bomBytes = IOUtils.toByteArray(byteOrderMarkInputStream);
        } catch (IOException e) {
            LOGGER.error("An unexpected error occurred while decoding BOM uploaded to project: {}", projectInfo.uuid(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return processUpload(projectInfo, bomBytes);
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Upload a supported bill of material format document",
            description = """
                    <p>
                      Expects CycloneDX and a valid project UUID. If a UUID is not specified,
                      then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                      Optionally, if <code>autoCreate</code> is specified and <code>true</code> and the project does not exist,
                      the project will be created. In this scenario, the principal making the request will
                      additionally need the <strong>PORTFOLIO_MANAGEMENT</strong>, <strong>PORTFOLIO_MANAGEMENT_CREATE</strong>,
                      or <strong>PROJECT_CREATION_UPLOAD</strong> permission.
                    </p>
                    <p>
                      MediaType supported for BOM artifact is 'application/xml' or 'application/json'.
                      The BOM will be validated against the CycloneDX schema. If schema validation fails,
                      a response with problem details in RFC 9457 format will be returned. In this case,
                      the response's content type will be <code>application/problem+json</code>.
                    </p>
                    <p>
                      The upload can target an existing project directly with <code>project</code>, or use
                      <code>projectName</code> and <code>projectVersion</code> to look up the project and,
                      with <code>autoCreate</code>, create it when it does not already exist. When creating
                      projects, <code>parentUUID</code> or <code>parentName</code> and
                      <code>parentVersion</code> can place the new project under a parent,
                      <code>projectTags</code> can apply tags, and <code>isLatest</code> can mark it as
                      the latest version. The <code>isActive</code> parameter sets the project's active
                      state whenever it is provided, including when the target project already exists, so
                      clients should send it only when they intend to change that state.
                    </p>
                    <p>Requires permission <strong>BOM_UPLOAD</strong></p>""",
            operationId = "UploadBom"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking BOM processing progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid BOM",
                    content = @Content(
                            schema = @Schema(implementation = InvalidBomProblemDetails.class),
                            mediaType = ProblemDetails.MEDIA_TYPE_JSON
                    )
            ),
            @ApiResponse(responseCode = "400", description = "The uploaded BOM is invalid"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(
            @FormDataParam("project") String projectUuid,
            @DefaultValue("false") @FormDataParam("autoCreate") boolean autoCreate,
            @FormDataParam("projectName") String projectName,
            @FormDataParam("projectVersion") String projectVersion,
            @FormDataParam("projectTags") String projectTags,
            @FormDataParam("parentName") String parentName,
            @FormDataParam("parentVersion") String parentVersion,
            @FormDataParam("parentUUID") String parentUUID,
            @DefaultValue("false") @FormDataParam("isLatest") boolean isLatest,
            @FormDataParam("isActive") Boolean isActive,
            @Parameter(schema = @Schema(type = "string")) @FormDataParam("bom") final List<FormDataBodyPart> artifactParts
    ) {
        if (artifactParts == null || artifactParts.isEmpty()) {
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("No BOM file provided.")
                    .build());
        }

        final List<Tag> requestTags = (projectTags != null && !projectTags.isBlank())
                ? Arrays.stream(projectTags.split(",")).map(String::trim).filter(not(String::isEmpty)).map(Tag::new).toList()
                : null;

        final ProjectInfo projectInfo;
        if (projectUuid != null) { // behavior in v3.0.0
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                projectInfo = qm.callInTransaction(() -> {
                    final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                    if (project == null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The project could not be found.")
                                .build());
                    }
                    requireAccess(qm, project);
                    if (project.getCollectionLogic() != null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("BOM cannot be uploaded to a collection project.")
                                .build());
                    }
                    maybeBindTags(qm, project, requestTags);
                    if (isActive != null) {
                        project.setActive(isActive);
                    }
                    return ProjectInfo.of(project);
                });
            }
        } else { // additional behavior added in v3.1.0
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                projectInfo = qm.callInTransaction(() -> {
                    final String trimmedProjectName = StringUtils.trimToNull(projectName);
                    final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);

                    // NB: Bypass portfolio ACL for this lookup since it would otherwise filter out existing
                    // projects that are inaccessible. `autoCreate=true` would then lead to us trying to create
                    // a project that already exists, triggering a unique constraint violation.
                    // Access to the project (and potentially its parent) is asserted explicitly via requireAccess().
                    Project project = ProjectAccess.unrestricted(
                            () -> qm.getProject(trimmedProjectName, trimmedProjectVersion));

                    if (project == null && autoCreate) {
                        if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                            Project parent = null;
                            if (parentUUID != null || parentName != null) {
                                if (parentUUID != null) {
                                    parent = qm.getObjectByUuid(Project.class, parentUUID);
                                } else {
                                    final String trimmedParentName = StringUtils.trimToNull(parentName);
                                    final String trimmedParentVersion = StringUtils.trimToNull(parentVersion);
                                    parent = ProjectAccess.unrestricted(() -> qm.getProject(trimmedParentName, trimmedParentVersion));
                                }

                                if (parent == null) {
                                    throw new WebApplicationException(Response
                                            .status(Response.Status.NOT_FOUND)
                                            .entity("The parent project could not be found.")
                                            .build());
                                }
                                requireAccess(qm, parent, "Access to the specified parent project is forbidden");
                            }
                            if (isLatest) {
                                final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(trimmedProjectName));
                                if (oldLatest != null) {
                                    requireAccess(qm, oldLatest, "Access to the previous latest project version is forbidden");
                                }
                            }
                            try {
                                project = qm.createProject(trimmedProjectName, null, trimmedProjectVersion, requestTags, parent,
                                        null, Boolean.FALSE.equals(isActive) ? Date.from(Instant.now()) : null, isLatest, true);
                            } catch (RuntimeException e) {
                                if (isUniqueConstraintViolation(e)) {
                                    throw new WebApplicationException(Response
                                            .status(Response.Status.CONFLICT)
                                            .entity("A project with the specified name and version already exists.")
                                            .build());
                                }
                                throw e;
                            }
                            Principal principal = getPrincipal();
                            qm.updateNewProjectACL(project, principal);
                            new JdoNotificationEmitter(qm).emit(
                                    createProjectCreatedNotification(
                                            NotificationModelConverter.convert(project)));
                        } else {
                            throw new WebApplicationException(Response
                                    .status(Response.Status.UNAUTHORIZED)
                                    .entity("The principal does not have permission to create project.")
                                    .build());
                        }
                    }

                    if (project == null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The project could not be found.")
                                .build());
                    }
                    requireAccess(qm, project);
                    if (project.getCollectionLogic() != null) {
                        throw new WebApplicationException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("BOM cannot be uploaded to a collection project.")
                                .build());
                    }
                    maybeBindTags(qm, project, requestTags);
                    if (isActive != null) {
                        project.setActive(isActive);
                    }
                    return ProjectInfo.of(project);
                });
            }
        }

        final FormDataBodyPart firstPart = artifactParts.getFirst();
        final byte[] bomBytes;
        try (final var inputStream = ((BodyPartEntity) firstPart.getEntity()).getInputStream();
             final var byteOrderMarkInputStream = BOMInputStream.builder().setInputStream(inputStream).get()) {
            bomBytes = IOUtils.toByteArray(byteOrderMarkInputStream);
        } catch (IOException e) {
            LOGGER.error("An unexpected error occurred while reading BOM from upload", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return processUpload(projectInfo, bomBytes);
    }

    private record ProjectInfo(UUID uuid, String name, String version, List<String> tagNames) {

        static ProjectInfo of(Project project) {
            return new ProjectInfo(
                    project.getUuid(),
                    project.getName(),
                    project.getVersion(),
                    project.getTags() != null
                            ? project.getTags().stream().map(Tag::getName).toList()
                            : List.of());
        }
    }

    // todo: make option to combine all the bom data so components are reconciled in a single pass.
    // todo: https://github.com/DependencyTrack/dependency-track/issues/130
    private Response processUpload(ProjectInfo project, byte[] bomBytes) {
        validateBom(bomBytes, project.tagNames(), project.uuid());

        final UUID bomUploadToken = Generators.timeBasedEpochRandomGenerator().generate();

        final FileMetadata bomFileMetadata;
        try {
            // TODO: Provide mediaType to FileStorage#store. Should be any of:
            //   * application/vnd.cyclonedx+json
            //   * application/vnd.cyclonedx+xml
            //  Consider also attaching the detected version, i.e. application/vnd.cyclonedx+xml; version=1.6
            //  See https://cyclonedx.org/specification/overview/ -> Media Types.
            bomFileMetadata = fileStorage.store(
                    "bom-upload/%s".formatted(bomUploadToken),
                    new ByteArrayInputStream(bomBytes));
        } catch (IOException e) {
            LOGGER.error("Failed to store BOM for project: {}", project.uuid(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        final var response = Response.ok(new BomUploadResponse(bomUploadToken, project.uuid())).build();

        try {
            dexEngine.createRun(
                    new CreateWorkflowRunRequest<>(ImportBomWorkflow.class)
                            .withConcurrencyKey("import-bom:%s".formatted(project.uuid()))
                            .withLabels(Map.ofEntries(
                                    Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString()),
                                    Map.entry(WF_LABEL_PROJECT_UUID, project.uuid().toString())))
                            .withArgument(ImportBomArg.newBuilder()
                                    .setProjectUuid(project.uuid().toString())
                                    .setProjectName(project.name())
                                    .setProjectVersion(project.version() != null ? project.version() : "")
                                    .setBomUploadToken(bomUploadToken.toString())
                                    .setBomFileMetadata(bomFileMetadata)
                                    .build()));

            try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, project.uuid().toString());
                 var _ = MDC.putCloseable(MDC_PROJECT_NAME, project.name());
                 var _ = MDC.putCloseable(MDC_PROJECT_VERSION, project.version());
                 var _ = MDC.putCloseable(MDC_BOM_UPLOAD_TOKEN, bomUploadToken.toString())) {
                LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "BOM upload accepted");
            }
        } catch (RuntimeException e) {
            try {
                fileStorage.delete(bomFileMetadata);
            } catch (IOException ex) {
                LOGGER.warn("Failed to cleanup BOM file {}", bomFileMetadata.getLocation(), ex);
                e.addSuppressed(ex);
            }
            throw e;
        }

        return response;
    }

    static void validate(byte[] bomBytes, Project project) {
        final List<String> tagNames = project.getTags() != null
                ? project.getTags().stream().map(org.dependencytrack.model.Tag::getName).toList()
                : List.of();
        validateBom(bomBytes, tagNames, project.getUuid());
    }

    private static void validateBom(
            byte[] bomBytes,
            List<String> projectTagNames,
            UUID projectUuid) {
        if (!shouldValidate(projectTagNames)) {
            return;
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

            useJdbiTransaction(handle -> {
                final List<org.dependencytrack.notification.proto.v1.Project> projects =
                        handle
                                .attach(NotificationSubjectDao.class)
                                .getProjects(List.of(projectUuid));
                if (!projects.isEmpty()) {
                    new JdbiNotificationEmitter(handle).emit(
                            createBomValidationFailedNotification(
                                    projects.getFirst(),
                                    e.getValidationErrors()));
                }
            });

            throw new WebApplicationException(problemDetails.toResponse());
        } catch (RuntimeException e) {
            LOGGER.error("Failed to validate BOM", e);
            throw new WebApplicationException(Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .build());
        }
    }

    @GET
    @Path("/token/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.",
            description = """
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
                    <p><strong>Deprecated</strong>. Use <code>/v1/event/token/{uuid}</code> instead.</p>""")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The processing status of the provided token",
                    content = @Content(schema = @Schema(implementation = IsTokenBeingProcessedResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    @Deprecated(since = "4.11.0")
    public Response isTokenBeingProcessed(
            @Parameter(description = "The UUID of the token to query", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        final UUID token = UUID.fromString(uuid);

        final boolean isProcessing;
        if (dexEngine.existsRun(
                new ExistsWorkflowRunRequest(
                        WorkflowRunStatus.NON_TERMINAL_STATUSES,
                        Map.of(WF_LABEL_BOM_UPLOAD_TOKEN, token.toString())))) {
            isProcessing = true;
        } else {
            final var runMetadata = dexEngine.getRunMetadataById(token);
            isProcessing = runMetadata != null && !runMetadata.status().isTerminal();
        }

        final var response = new IsTokenBeingProcessedResponse();
        response.setProcessing(isProcessing);
        return Response.ok(response).build();
    }

    private static boolean shouldValidate(List<String> projectTagNames) {
        try (final var qm = new QueryManager()) {
            final ConfigProperty validationModeProperty = qm.getConfigProperty(
                    BOM_VALIDATION_MODE.getGroupName(),
                    BOM_VALIDATION_MODE.getPropertyName()
            );

            var validationMode = BomValidationMode.valueOf(BOM_VALIDATION_MODE.getDefaultPropertyValue());
            try {
                validationMode = BomValidationMode.valueOf(validationModeProperty.getPropertyValue());
            } catch (RuntimeException e) {
                LOGGER.warn("""
                        No BOM validation mode configured, or configured value is invalid; \
                        Assuming default mode %s""".formatted(validationMode), e);
            }

            if (validationMode == BomValidationMode.ENABLED) {
                LOGGER.debug("Validating BOM because validation is enabled globally");
                return true;
            } else if (validationMode == BomValidationMode.DISABLED) {
                LOGGER.debug("Not validating BOM because validation is disabled globally");
                return false;
            }

            // Other modes depend on tags. Does the project even have tags?
            if (projectTagNames.isEmpty()) {
                return validationMode == BomValidationMode.DISABLED_FOR_TAGS;
            }

            final ConfigPropertyConstants tagsPropertyConstant = validationMode == BomValidationMode.ENABLED_FOR_TAGS
                    ? BOM_VALIDATION_TAGS_INCLUSIVE
                    : BOM_VALIDATION_TAGS_EXCLUSIVE;
            final ConfigProperty tagsProperty = qm.getConfigProperty(
                    tagsPropertyConstant.getGroupName(),
                    tagsPropertyConstant.getPropertyName()
            );

            final Set<String> validationModeTags;
            try {
                final JsonReader jsonParser = Json.createReader(new StringReader(tagsProperty.getPropertyValue()));
                final JsonArray jsonArray = jsonParser.readArray();
                validationModeTags = Set.copyOf(jsonArray.getValuesAs(JsonString::getString));
            } catch (RuntimeException e) {
                LOGGER.warn("Tags of property %s:%s could not be parsed as JSON array"
                        .formatted(tagsPropertyConstant.getGroupName(), tagsPropertyConstant.getPropertyName()), e);
                return validationMode == BomValidationMode.DISABLED_FOR_TAGS;
            }

            final boolean doTagsMatch = projectTagNames.stream()
                    .anyMatch(validationModeTags::contains);
            return (validationMode == BomValidationMode.ENABLED_FOR_TAGS && doTagsMatch)
                    || (validationMode == BomValidationMode.DISABLED_FOR_TAGS && !doTagsMatch);
        }
    }

    private void maybeBindTags(QueryManager qm, Project project, List<Tag> tags) {
        if (tags == null) {
            return;
        }

        // If the principal has the PROJECT_CREATION_UPLOAD permission,
        // and a new project was created as part of this upload,
        // the project might already have the requested tags.
        final Set<String> existingTagNames = project.getTags() != null
                ? project.getTags().stream().map(Tag::getName).collect(Collectors.toSet())
                : Collections.emptySet();
        final Set<String> requestTagNames = tags.stream()
                .filter(Objects::nonNull)
                .map(Tag::getName)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        if (!Objects.equals(existingTagNames, requestTagNames)
                && !hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT)
                && !hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE)) {
            // Most CI integrations will use API keys with PROJECT_CREATION_UPLOAD permission,
            // but not PORTFOLIO_MANAGEMENT(_UPDATE) permission. They will not send different
            // upload requests though, after a project was first created. Failing the request
            // would break those integrations. Log a warning instead.
            LOGGER.warn("""
                    Project tags were provided as part of the BOM upload request, \
                    but the authenticated principal is missing the %s or %s permission; \
                    Tags will not be modified""".formatted(
                    Permissions.Constants.PORTFOLIO_MANAGEMENT,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE));
            return;
        }

        final Set<Tag> resolvedTags = qm.resolveTags(tags);
        qm.bind(project, resolvedTags);
    }

}
