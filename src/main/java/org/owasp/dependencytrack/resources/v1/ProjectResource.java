/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
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
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjects() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getProjects();
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
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProject(
            @ApiParam(value = "The UUID of the project to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                return Response.ok(project).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new project",
            notes = "Requires 'manage project' permission. If a parent project exists, the UUID of the parent project is required ",
            response = Project.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A project with the specified name already exists")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response createProject(Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version")
        );

        try (QueryManager qm = new QueryManager()) {
            Project parent = null;
            if (jsonProject.getParent() != null && jsonProject.getParent().getUuid() != null) {
                parent = qm.getObjectByUuid(Project.class, jsonProject.getParent().getUuid());
            }
            Project project = qm.getProject(jsonProject.getName().trim());
            if (project == null) {
                project = qm.createProject(
                        jsonProject.getName().trim(),
                        StringUtils.trimToNull(jsonProject.getDescription()),
                        StringUtils.trimToNull(jsonProject.getVersion()),
                        jsonProject.getTags(),
                        parent,
                        true);
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
            notes = "Requires 'manage project' permission.",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found"),
            @ApiResponse(code = 409, message = "A project with the specified name already exists")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response updateProject(Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version")
        );

        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, jsonProject.getUuid());
            if (project != null) {
                final Project tmpProject = qm.getProject(jsonProject.getName().trim());
                if (tmpProject == null || (tmpProject.getUuid().equals(project.getUuid()))) {
                    project = qm.updateProject(
                            jsonProject.getUuid(),
                            jsonProject.getName().trim(),
                            StringUtils.trimToNull(jsonProject.getDescription()),
                            StringUtils.trimToNull(jsonProject.getVersion()),
                            jsonProject.getTags(),
                            true);
                    return Response.ok(project).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A project with the specified name already exists.").build();
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
            notes = "Requires 'manage project' permission.",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response deleteProject(
            @ApiParam(value = "The UUID of the project to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
            if (project != null) {
                qm.recursivelyDeleteProject(project);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

}
