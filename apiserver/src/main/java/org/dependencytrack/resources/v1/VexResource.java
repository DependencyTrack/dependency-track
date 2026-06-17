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
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
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
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.CycloneDxMediaType;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.ProjectAccess;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.internal.workflow.v1.ImportVexArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.InvalidBomProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.VexSubmitRequest;
import org.dependencytrack.tasks.ImportVexWorkflow;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_VEX_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_VEX_UPLOAD_TOKEN;

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
public class VexResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(VexResource.class);
    private static final String DEFAULT_EXPORT_VERSION = "1.5";

    private final DexEngine dexEngine;
    private final FileStorage fileStorage;

    @Inject
    public VexResource(DexEngine dexEngine, FileStorage fileStorage) {
        this.dexEngine = dexEngine;
        this.fileStorage = fileStorage;
    }

    @GET
    @Path("/cyclonedx/project/{uuid}")
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON, MediaType.APPLICATION_OCTET_STREAM})
    @Operation(
            summary = "Returns a VEX for a project in CycloneDX format",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong> or <strong>VULNERABILITY_ANALYSIS_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A VEX for a project in CycloneDX format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.VIEW_VULNERABILITY,
            Permissions.Constants.VULNERABILITY_ANALYSIS,
            Permissions.Constants.VULNERABILITY_ANALYSIS_READ})
    public Response exportProjectAsCycloneDx(
            @Parameter(description = "The UUID of the project to export", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Force the resulting VEX to be downloaded as a file (defaults to 'false')")
            @QueryParam("download") boolean download,
            @Parameter(description = "The CycloneDX Spec variant exported (defaults to: '" + DEFAULT_EXPORT_VERSION + "')")
            @QueryParam("version") String version
    ) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            String versionParameter = Objects.toString(StringUtils.trimToNull(version), DEFAULT_EXPORT_VERSION);
            Version cdxOutputVersion = Version.fromVersionString(versionParameter);
            if (cdxOutputVersion == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid CycloneDX version specified.").build();
            }

            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);

            final CycloneDXExporter exporter = new CycloneDXExporter(CycloneDXExporter.Variant.VEX, qm);

            try {
                if (download) {
                    return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON, cdxOutputVersion), MediaType.APPLICATION_OCTET_STREAM)
                            .header("content-disposition", "attachment; filename=\"" + project.getUuid() + "-vex.cdx.json\"").build();
                } else {
                    return Response.ok(exporter.export(exporter.create(project), CycloneDXExporter.Format.JSON, cdxOutputVersion),
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
                    <p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong> or <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>"""
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({Permissions.Constants.VULNERABILITY_ANALYSIS, Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE})
    public Response uploadVex(VexSubmitRequest request) {
        final Validator validator = getValidator();
        if (request.getProject() != null) {
            failOnValidationError(
                    validator.validateProperty(request, "project"),
                    validator.validateProperty(request, "vex")
            );
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                return qm.callInTransaction(() -> {
                    final Project project = qm.getObjectByUuid(Project.class, request.getProject());
                    return process(qm, project, request.getVex());
                });
            }
        } else {
            failOnValidationError(
                    validator.validateProperty(request, "projectName"),
                    validator.validateProperty(request, "projectVersion"),
                    validator.validateProperty(request, "vex")
            );
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                return qm.callInTransaction(() -> {
                    Project project = ProjectAccess.unrestricted(() -> qm.getProject(request.getProjectName(), request.getProjectVersion()));
                    return process(qm, project, request.getVex());
                });
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
                    <p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong> or <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>"""
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({Permissions.Constants.VULNERABILITY_ANALYSIS, Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE})
    public Response uploadVex(@FormDataParam("project") String projectUuid,
                              @FormDataParam("projectName") String projectName,
                              @FormDataParam("projectVersion") String projectVersion,
                              @Parameter(schema = @Schema(type = "string")) @FormDataParam("vex") final List<FormDataBodyPart> artifactParts) {
        if (projectUuid != null) {
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                return qm.callInTransaction(() -> {
                    final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                    return process(qm, project, artifactParts);
                });
            }
        } else {
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                return qm.callInTransaction(() -> {
                    final String trimmedProjectName = StringUtils.trimToNull(projectName);
                    final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);
                    Project project = ProjectAccess.unrestricted(() -> qm.getProject(trimmedProjectName, trimmedProjectVersion));
                    return process(qm, project, artifactParts);
                });
            }
        }
    }

    /**
     * Common logic that processes a VEX given a project and encoded payload.
     */
    private Response process(QueryManager qm, Project project, String encodedVexData) {
        if (project != null) {
            requireAccess(qm, project);
            if (project.getCollectionLogic() != null) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("VEX cannot be uploaded to a collection project.")
                        .build();
            }
            final byte[] decoded = Base64.getDecoder().decode(encodedVexData);
            BomResource.validate(decoded, project);
            return startVexImport(project, decoded);
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

    /**
     * Common logic that processes a VEX given a project and list of multi-party form objects containing decoded payloads.
     */
    private Response process(QueryManager qm, Project project, List<FormDataBodyPart> artifactParts) {
        for (final FormDataBodyPart artifactPart : artifactParts) {
            final BodyPartEntity bodyPartEntity = (BodyPartEntity) artifactPart.getEntity();
            if (project != null) {
                requireAccess(qm, project);
                if (project.getCollectionLogic() != null) {
                    return Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("VEX cannot be uploaded to a collection project.")
                            .build();
                }
                try (InputStream in = bodyPartEntity.getInputStream()) {
                    final byte[] content = IOUtils.toByteArray(BOMInputStream.builder().setInputStream(in).get());
                    BomResource.validate(content, project);
                    return startVexImport(project, content);
                } catch (IOException e) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
        return Response.ok().build();
    }

    private Response startVexImport(Project project, byte[] vexBytes) {
        final UUID vexUploadToken = Generators.timeBasedEpochRandomGenerator().generate();

        final FileMetadata vexFileMetadata;
        try {
            vexFileMetadata = fileStorage.store(
                    "vex-upload/%s".formatted(vexUploadToken),
                    new ByteArrayInputStream(vexBytes));
        } catch (IOException e) {
            LOGGER.error("Failed to store VEX for project: {}", project.getUuid(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        final UUID runId;
        try {
            runId = dexEngine.createRun(
                    new CreateWorkflowRunRequest<>(ImportVexWorkflow.class)
                            .withConcurrencyKey("import-vex:%s".formatted(project.getUuid()))
                            .withLabels(Map.ofEntries(
                                    Map.entry(WF_LABEL_VEX_UPLOAD_TOKEN, vexUploadToken.toString()),
                                    Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString())))
                            .withArgument(ImportVexArg.newBuilder()
                                    .setProjectUuid(project.getUuid().toString())
                                    .setProjectName(project.getName())
                                    .setProjectVersion(project.getVersion() != null
                                            ? project.getVersion()
                                            : "")
                                    .setVexUploadToken(vexUploadToken.toString())
                                    .setVexFileMetadata(vexFileMetadata)
                                    .build()));

            try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, project.getUuid().toString());
                 var _ = MDC.putCloseable(MDC_PROJECT_NAME, project.getName());
                 var _ = MDC.putCloseable(MDC_PROJECT_VERSION, project.getVersion());
                 var _ = MDC.putCloseable(MDC_VEX_UPLOAD_TOKEN, vexUploadToken.toString())) {
                LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "VEX upload accepted");
            }
        } catch (RuntimeException e) {
            try {
                fileStorage.delete(vexFileMetadata);
            } catch (IOException ex) {
                LOGGER.warn("Failed to cleanup VEX file {}", vexFileMetadata.getLocation(), ex);
                e.addSuppressed(ex);
            }
            throw e;
        }

        return Response
                .ok(new BomUploadResponse(runId, project.getUuid()))
                .build();
    }

}
