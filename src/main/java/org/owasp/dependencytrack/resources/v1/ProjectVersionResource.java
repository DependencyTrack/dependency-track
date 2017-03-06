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
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectVersion;
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
import java.util.List;

@Path("/v1/project")
@Api(value = "projectversion", authorizations = @Authorization(value="X-Api-Key"))
public class ProjectVersionResource extends AlpineResource {

    @GET
    @Path("/{uuid}/versions")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all project versions for the specified project",
            response = ProjectVersion.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjectVersions(
            @ApiParam(value = "The UUID of the project to retrieve project versions for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
            if (project != null) {
                List<ProjectVersion> versions = project.getProjectVersions();
                return Response.ok(versions).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/version/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific project version",
            response = ProjectVersion.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project version could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjectVersion(
            @ApiParam(value = "The UUID of the project version to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            ProjectVersion version = qm.getObjectByUuid(ProjectVersion.class, uuid);
            if (version != null) {
                return Response.ok(version).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project version could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new project version",
            notes = "Requires 'manage project' permission.",
            response = ProjectVersion.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found"),
            @ApiResponse(code = 409, message = "A project with the same version already exists")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response createProjectVersion(
            @ApiParam(value = "The UUID of the project to create a version for", required = true)
            @PathParam("uuid") String uuid,
            ProjectVersion jsonVersion) {
        Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonVersion, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
            if (project != null) {
                List<ProjectVersion> versions = project.getProjectVersions();
                boolean exists = false;
                for (ProjectVersion version: versions) {
                    if (version.getVersion().equalsIgnoreCase(jsonVersion.getVersion())) {
                        exists = true;
                    }
                }
                if (!exists) {
                    ProjectVersion version = qm.createProjectVersion(project, jsonVersion.getVersion());
                    return Response.ok(version).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A project with the same version already exists.").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @POST
    @Path("/version")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a project version",
            notes = "Requires 'manage project' permission",
            response = ProjectVersion.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project version could not be found")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response updateProjectVersion(ProjectVersion jsonVersion) {
        try (QueryManager qm = new QueryManager()) {
            ProjectVersion version = qm.getObjectByUuid(ProjectVersion.class, jsonVersion.getUuid());
            if (version != null) {
                version.setVersion(jsonVersion.getVersion());
                version = qm.updateProjectVersion(jsonVersion);
                return Response.ok(version).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project version could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/version/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a project version",
            notes = "Requires 'manage project' permission.",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project version could not be found")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response deleteProjectVersion(
            @ApiParam(value = "The UUID of the project version to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            ProjectVersion version = qm.getObjectByUuid(ProjectVersion.class, uuid, Project.FetchGroup.ALL.name());
            if (version != null) {
                qm.delete(version.getProperties());
                qm.delete(version);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project version could not be found.").build();
            }
        }
    }

}
