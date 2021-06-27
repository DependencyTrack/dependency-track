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
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/project")
@Api(value = "project", authorizations = @Authorization(value = "X-Api-Key"))
public class ProjectResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(ProjectResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all projects",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjects(@ApiParam(value = "The optional name of the project to query on", required = false)
                                @QueryParam("name") String name,
                                @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
                                @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = (name != null) ? qm.getProjects(name, excludeInactive) : qm.getProjects(true, excludeInactive);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific project",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProject(
            @ApiParam(value = "The UUID of the project to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.ok(project).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/lookup")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific project by its name and version",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProject(
            @ApiParam(value = "The name of the project to query on", required = true)
            @QueryParam("name") String name,
            @ApiParam(value = "The version of the project to query on", required = true)
            @QueryParam("version") String version) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getProject(name, version);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.ok(project).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/tag/{tag}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all projects by tag",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects with the tag")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsByTag(
            @ApiParam(value = "The tag to query on", required = true)
            @PathParam("tag") String tagString) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {

            final Tag tag = qm.getTagByName(tagString);
            final PaginatedResult result = qm.getProjects(tag, true);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new project",
            notes = "If a parent project exists, the UUID of the parent project is required ",
            response = Project.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A project with the specified name already exists")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createProject(Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "author"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId")
        );
        if (jsonProject.getClassifier() == null) {
            jsonProject.setClassifier(Classifier.APPLICATION);
        }
        try (QueryManager qm = new QueryManager()) {
            if (jsonProject.getParent() != null && jsonProject.getParent().getUuid() != null) {
                jsonProject.setParent(qm.getObjectByUuid(Project.class, jsonProject.getParent().getUuid()));
            }
            Project project = qm.getProject(StringUtils.trimToNull(jsonProject.getName()), StringUtils.trimToNull(jsonProject.getVersion()));
            if (project == null) {
                project = qm.createProject(jsonProject, jsonProject.getTags(), true);
                LOGGER.info("Project " + project.toString() + " created by " + super.getPrincipal().getName());
                return Response.status(Response.Status.CREATED).entity(project).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A project with the specified name already exists.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a project",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found"),
            @ApiResponse(code = 409, message = "A project with the specified name already exists")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response updateProject(Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "author"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId")
        );
        if (jsonProject.getClassifier() == null) {
            jsonProject.setClassifier(Classifier.APPLICATION);
        }
        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, jsonProject.getUuid());
            if (project != null) {
                final String name = StringUtils.trimToNull(jsonProject.getName());
                final String version = StringUtils.trimToNull(jsonProject.getVersion());
                final Project tmpProject = qm.getProject(name, version);
                if (tmpProject == null || (tmpProject.getUuid().equals(project.getUuid()))) {
                    // Name cannot be empty or null - prevent it
                    if (name == null) {
                        jsonProject.setName(project.getName());
                    }
                    project = qm.updateProject(jsonProject, true);
                    LOGGER.info("Project " + project.toString() + " updated by " + super.getPrincipal().getName());
                    return Response.ok(project).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A project with the specified name and version already exists.").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a project",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteProject(
            @ApiParam(value = "The UUID of the project to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    LOGGER.info("Project " + project.toString() + " deletion request by " + super.getPrincipal().getName());
                    qm.recursivelyDelete(project);
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/clone")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Clones a project",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response cloneProject(CloneProjectRequest jsonRequest) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRequest, "project"),
                validator.validateProperty(jsonRequest, "version")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project sourceProject = qm.getObjectByUuid(Project.class, jsonRequest.getProject(), Project.FetchGroup.ALL.name());
            if (sourceProject != null) {
                LOGGER.info("Project " + sourceProject.toString() + " is being cloned by " + super.getPrincipal().getName());
                Event.dispatch(new CloneProjectEvent(jsonRequest));
                return Response.ok().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }
}
