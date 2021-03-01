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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.event.framework.Event;
import alpine.logging.Logger;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxMediaType;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
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
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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
    @Produces({CycloneDxMediaType.APPLICATION_CYCLONEDX_XML, CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON})
    @ApiOperation(
            value = "Returns dependency metadata for a project in CycloneDX format",
            response = String.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportProjectAsCycloneDx (
            @ApiParam(value = "The UUID of the project to export", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "The format to output (defaults to xml)")
            @QueryParam("format") String format) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final List<Component> components = qm.getAllComponents(project);
            final List<ServiceComponent> services = qm.getAllServiceComponents(project);
            final List<org.cyclonedx.model.Component> cycloneComponents = components.stream().map(component -> ModelConverter.convert(qm, component)).collect(Collectors.toList());
            final List<org.cyclonedx.model.Service> cycloneServices = services.stream().map(service -> ModelConverter.convert(qm, service)).collect(Collectors.toList());
            try {
                final Bom bom = new Bom();
                bom.setSerialNumber("urn:uuid:" + UUID.randomUUID().toString());
                bom.setVersion(1);
                bom.setMetadata(ModelConverter.createMetadata(project));
                bom.setComponents(cycloneComponents);
                bom.setServices(cycloneServices);
                if (StringUtils.trimToNull(format) == null || format.equalsIgnoreCase("XML")) {
                    final BomXmlGenerator bomGenerator = BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom);
                    bomGenerator.generate();
                    return Response.ok(bomGenerator.toXmlString(), CycloneDxMediaType.APPLICATION_CYCLONEDX_XML).build();
                } else if (format.equalsIgnoreCase("JSON")) {
                    final BomJsonGenerator bomGenerator = BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, bom);
                    bomGenerator.generate();
                    return Response.ok(bomGenerator.toJsonString(), CycloneDxMediaType.APPLICATION_CYCLONEDX_JSON).build();
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid BOM format specified.").build();
                }
            } catch (ParserConfigurationException | GeneratorException e) {
                LOGGER.error("An error occurred while building a CycloneDX document for export", e);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        }
    }

    @GET
    @Path("/cyclonedx/components")
    @Produces(CycloneDxMediaType.APPLICATION_CYCLONEDX_XML)
    @ApiOperation(
            value = "Returns dependency metadata for all components in CycloneDX format",
            response = String.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportComponentsAsCycloneDx () {
        try (QueryManager qm = new QueryManager()) {
            final List<Component> components = qm.getAllComponents();
            final List<ServiceComponent> services = qm.getAllServiceComponents();
            final List<org.cyclonedx.model.Component> cycloneComponents = components.stream().map(component -> ModelConverter.convert(qm, component)).collect(Collectors.toList());
            final List<org.cyclonedx.model.Service> cycloneServices = services.stream().map(service -> ModelConverter.convert(qm, service)).collect(Collectors.toList());
            try {
                Bom bom = new Bom();
                bom.setSerialNumber("urn:ufuid:" + UUID.randomUUID().toString());
                bom.setVersion(1);
                bom.setMetadata(ModelConverter.createMetadata(null));
                bom.setComponents(cycloneComponents);
                bom.setServices(cycloneServices);
                final BomXmlGenerator bomXmlGenerator = BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom);
                bomXmlGenerator.generate();
                return Response.ok(bomXmlGenerator.toXmlString(), CycloneDxMediaType.APPLICATION_CYCLONEDX_XML).build();
            } catch (ParserConfigurationException | GeneratorException e) {
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
            response = String.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response exportComponentAsCycloneDx (
            @ApiParam(value = "The UUID of the component to export", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            try {
                final List<org.cyclonedx.model.Component> cycloneComponents = new ArrayList<>();
                cycloneComponents.add(ModelConverter.convert(qm, component));
                Bom bom = new Bom();
                bom.setSerialNumber("urn:uuid:" + UUID.randomUUID().toString());
                bom.setVersion(1);
                bom.setMetadata(ModelConverter.createMetadata(null));
                bom.setComponents(cycloneComponents);
                final BomXmlGenerator bomXmlGenerator = BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom);
                bomXmlGenerator.generate();
                return Response.ok(bomXmlGenerator.toXmlString(), CycloneDxMediaType.APPLICATION_CYCLONEDX_XML).build();
            } catch (ParserConfigurationException | GeneratorException e) {
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
            notes = "Expects CycloneDX or SPDX (tag or RDF) along and a valid project UUID. If a UUID is not specified then the projectName and projectVersion must be specified. Optionally, if autoCreate is specified and 'true' and the project does not exist, the project will be created. In this scenario, the principal making the request will additionally need the PORTFOLIO_MANAGEMENT or PROJECT_CREATION_UPLOAD permission."
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
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        project = qm.createProject(StringUtils.trimToNull(request.getProjectName()), null, StringUtils.trimToNull(request.getProjectVersion()), null, null, null, true, true);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(project, request.getBom());
            }
        }
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Upload a supported bill of material format document",
            notes = "Expects CycloneDX or SPDX (text or RDF) along and a valid project UUID. If a UUID is not specified, than the projectName and projectVersion must be specified. Optionally, if autoCreate is specified and 'true' and the project does not exist, the project will be created. In this scenario, the principal making the request will additionally need the PORTFOLIO_MANAGEMENT or PROJECT_CREATION_UPLOAD permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response uploadBom(@FormDataParam("project") String projectUuid,
                               @DefaultValue("false") @FormDataParam("autoCreate") boolean autoCreate,
                               @FormDataParam("projectName") String projectName,
                               @FormDataParam("projectVersion") String projectVersion,
                               final FormDataMultiPart multiPart) {

        final List<FormDataBodyPart> artifactParts = multiPart.getFields("bom");
        if (projectUuid != null) { // behavior in v3.0.0
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                return process(project, artifactParts);
            }
        } else { // additional behavior added in v3.1.0
            try (QueryManager qm = new QueryManager()) {
                final String trimmedProjectName = StringUtils.trimToNull(projectName);
                final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);
                Project project = qm.getProject(trimmedProjectName, trimmedProjectVersion);
                if (project == null && autoCreate) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) || hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {
                        project = qm.createProject(trimmedProjectName, null, trimmedProjectVersion, null, null, null, true, true);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED).entity("The principal does not have permission to create project.").build();
                    }
                }
                return process(project, artifactParts);
            }
        }
    }

    @GET
    @Path("/token/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.",
            notes = "This endpoint is intended to be used in conjunction with uploading a supported BOM document. Upon upload, a token will be returned. The token can then be queried using this endpoint to determine if any tasks (such as vulnerability analysis) is being performed on the BOM. A value of true indicates processing is occurring. A value of false indicates that no processing is occurring for the specified token. However, a value of false also does not confirm the token is valid, only that no processing is associated with the specified token."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response isTokenBeingProcessed (
            @ApiParam(value = "The UUID of the token to query", required = true)
            @PathParam("uuid") String uuid) {

        final boolean value = Event.isEventBeingProcessed(UUID.fromString(uuid));
        return Response.ok(Collections.singletonMap("processing", value)).build();
    }

    /**
     * Common logic that processes a BOM given a project and encoded payload.
     */
    private Response process(Project project, String encodedBomData) {
        if (project != null) {
            final byte[] decoded = Base64.getDecoder().decode(encodedBomData);
            final BomUploadEvent bomUploadEvent = new BomUploadEvent(project.getUuid(), decoded);
            Event.dispatch(bomUploadEvent);
            return Response.ok(Collections.singletonMap("token", bomUploadEvent.getChainIdentifier())).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
        }
    }

    /**
     * Common logic that processes a BOM given a project and list of multi-party form objects containing decoded payloads.
     */
    private Response process(Project project, List<FormDataBodyPart> artifactParts) {
        for (final FormDataBodyPart artifactPart: artifactParts) {
            final BodyPartEntity bodyPartEntity = (BodyPartEntity) artifactPart.getEntity();
            if (project != null) {
                try (InputStream in = bodyPartEntity.getInputStream()) {
                    final byte[] content = IOUtils.toByteArray(in);
                    // todo: make option to combine all the bom data so components are reconciled in a single pass.
                    // todo: https://github.com/DependencyTrack/dependency-track/issues/130
                    final BomUploadEvent bomUploadEvent = new BomUploadEvent(project.getUuid(), content);
                    Event.dispatch(bomUploadEvent);
                    return Response.ok(Collections.singletonMap("token", bomUploadEvent.getChainIdentifier())).build();
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
