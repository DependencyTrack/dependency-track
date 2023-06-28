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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.jsonwebtoken.lang.Collections;
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
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import javax.jdo.FetchGroup;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PATCH;
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
                                @QueryParam("excludeInactive") boolean excludeInactive,
                                @ApiParam(value = "Optionally excludes children projects from being returned", required = false)
                                @QueryParam("onlyRoot") boolean onlyRoot) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = (name != null) ? qm.getProjects(name, excludeInactive, onlyRoot) : qm.getProjects(true, excludeInactive, onlyRoot);
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
            final Project project = qm.getProject(uuid);
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
    @ApiOperation(value = "Returns a specific project by its name and version", response = Project.class, nickname = "getProjectByNameAndVersion")
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
            @PathParam("tag") String tagString,
            @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive,
            @ApiParam(value = "Optionally excludes children projects from being returned", required = false)
            @QueryParam("onlyRoot") boolean onlyRoot) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Tag tag = qm.getTagByName(tagString);
            final PaginatedResult result = qm.getProjects(tag, true, excludeInactive, onlyRoot);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/classifier/{classifier}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all projects by classifier",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects of the specified classifier")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsByClassifier(
            @ApiParam(value = "The classifier to query on", required = true)
            @PathParam("classifier") String classifierString,
            @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive,
            @ApiParam(value = "Optionally excludes children projects from being returned", required = false)
            @QueryParam("onlyRoot") boolean onlyRoot) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Classifier classifier = Classifier.valueOf(classifierString);
            final PaginatedResult result = qm.getProjects(classifier, true, excludeInactive, onlyRoot);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The classifier type specified is not valid.").build();
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
            @ApiResponse(code = 409, message = "- An inactive Parent cannot be selected as parent\n- A project with the specified name already exists"),
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
                Project parent = qm.getObjectByUuid(Project.class, jsonProject.getParent().getUuid());
                    jsonProject.setParent(parent);
            }
            Project project = qm.getProject(StringUtils.trimToNull(jsonProject.getName()), StringUtils.trimToNull(jsonProject.getVersion()));
            if (project == null) {
                try {
                    project = qm.createProject(jsonProject, jsonProject.getTags(), true);
                } catch (IllegalArgumentException e){
                    LOGGER.debug(e.getMessage());
                    return Response.status(Response.Status.CONFLICT).entity("An inactive Parent cannot be selected as parent").build();
                }
                Principal principal = getPrincipal();
                qm.updateNewProjectACL(project, principal);
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
            @ApiResponse(code = 409, message = "- An inactive Parent cannot be selected as parent\n- Project cannot be set to inactive if active children are present\n- A project with the specified name already exists\n- A project cannot select itself as a parent")
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
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                final String name = StringUtils.trimToNull(jsonProject.getName());
                final String version = StringUtils.trimToNull(jsonProject.getVersion());
                final Project tmpProject = qm.getProject(name, version);
                if (tmpProject == null || (tmpProject.getUuid().equals(project.getUuid()))) {
                    // Name cannot be empty or null - prevent it
                    if (name == null) {
                        jsonProject.setName(project.getName());
                    }
                    try {
                        project = qm.updateProject(jsonProject, true);
                    } catch (IllegalArgumentException e){
                        LOGGER.debug(e.getMessage());
                        return Response.status(Response.Status.CONFLICT).entity(e.getMessage()).build();
                    }
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

    @PATCH
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Partially updates a project",
            response = Project.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found"),
            @ApiResponse(code = 409, message = "- An inactive Parent cannot be selected as parent\n- Project cannot be set to inactive if active children are present\n- A project with the specified name already exists\n- A project cannot select itself as a parent")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response patchProject(
            @ApiParam(value = "The UUID of the project to modify", required = true)
            @PathParam("uuid") String uuid,
            Project jsonProject) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "author"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                jsonProject.getName() != null ? validator.validateProperty(jsonProject, "name") : Set.of(),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId")
        );

        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                var modified = false;
                project = qm.detachWithGroups(project, List.of(FetchGroup.DEFAULT, Project.FetchGroup.PARENT.name()));
                modified |= setIfDifferent(jsonProject, project, Project::getName, Project::setName);
                modified |= setIfDifferent(jsonProject, project, Project::getVersion, Project::setVersion);
                // if either name or version has been changed, verify that this new combination does not already exist
                if (modified && qm.getProject(project.getName(), project.getVersion()) != null) {
                    return Response.status(Response.Status.CONFLICT).entity("A project with the specified name and version already exists.").build();
                }
                modified |= setIfDifferent(jsonProject, project, Project::getAuthor, Project::setAuthor);
                modified |= setIfDifferent(jsonProject, project, Project::getPublisher, Project::setPublisher);
                modified |= setIfDifferent(jsonProject, project, Project::getGroup, Project::setGroup);
                modified |= setIfDifferent(jsonProject, project, Project::getDescription, Project::setDescription);
                modified |= setIfDifferent(jsonProject, project, Project::getClassifier, Project::setClassifier);
                modified |= setIfDifferent(jsonProject, project, Project::getCpe, Project::setCpe);
                modified |= setIfDifferent(jsonProject, project, Project::getPurl, Project::setPurl);
                modified |= setIfDifferent(jsonProject, project, Project::getSwidTagId, Project::setSwidTagId);
                modified |= setIfDifferent(jsonProject, project, Project::isActive, Project::setActive);
                if (jsonProject.getParent() != null && jsonProject.getParent().getUuid() != null) {
                    final Project parent = qm.getObjectByUuid(Project.class, jsonProject.getParent().getUuid());
                    if (parent == null) {
                        return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the parent project could not be found.").build();
                    }
                    if (!qm.hasAccess(getPrincipal(), parent)) {
                        return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified parent project is forbidden").build();
                    }
                    modified |= project.getParent() == null || !parent.getUuid().equals(project.getParent().getUuid());
                    project.setParent(parent);
                }
                if (isCollectionModified(jsonProject.getTags(), project.getTags())) {
                    modified = true;
                    project.setTags(jsonProject.getTags());
                }
                if (isCollectionModified(jsonProject.getExternalReferences(), project.getExternalReferences())) {
                   modified = true;
                   project.setExternalReferences(jsonProject.getExternalReferences());
                }
                if (modified) {
                    try {
                        project = qm.updateProject(project, true);
                    } catch (IllegalArgumentException e){
                        LOGGER.debug(e.getMessage());
                        return Response.status(Response.Status.CONFLICT).entity(e.getMessage()).build();
                    }
                    LOGGER.info("Project " + project.toString() + " updated by " + super.getPrincipal().getName());
                    return Response.ok(project).build();
                } else {
                    return Response.notModified().build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    /**
     * returns `true` if the given [updated] collection should be considered an update of the [original] collection.
     */
    private static <T> boolean isCollectionModified(Collection<T> updated, Collection<T> original) {
       return updated != null && (!Collections.isEmpty(updated) || !Collections.isEmpty(original));
    }

    /**
     * updates the given target object using the supplied setter method with the
     * new value from the source object using the supplied getter method. But
     * only if the new value is not {@code null} and it is not
     * {@link Object#equals(java.lang.Object) equal to} the old value.
     *
     * @param <T> the type of the old and new value
     * @param source the source object that contains the new value
     * @param target the target object that should be updated
     * @param getter the method to retrieve the new value from {@code source}
     * and the old value from {@code target}
     * @param setter the method to set the new value on {@code target}
     * @return {@code true} if {@code target} has been changed, else
     * {@code false}
     */
    private <T> boolean setIfDifferent(final Project source, final Project target, final Function<Project, T> getter, final BiConsumer<Project, T> setter) {
        final T newValue = getter.apply(source);
        if (newValue != null && !newValue.equals(getter.apply(target))) {
            setter.accept(target, newValue);
            return true;
        } else {
            return false;
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
                    LOGGER.info("Project " + project + " deletion request by " + super.getPrincipal().getName());
                    qm.recursivelyDelete(project, true);
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


    @GET
    @Path("/{uuid}/children")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all children for a project",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjects(@ApiParam(value = "The UUID of the project to get the children from", required = true)
                                            @PathParam("uuid") String uuid,
                                        @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
                                        @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final PaginatedResult result = qm.getChildrenProjects(project.getUuid(), true, excludeInactive);
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/{uuid}/children/classifier/{classifier}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all children for a project by classifier",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjectsByClassifier(
            @ApiParam(value = "The classifier to query on", required = true)
            @PathParam("classifier") String classifierString,
            @ApiParam(value = "The UUID of the project to get the children from", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final Classifier classifier = Classifier.valueOf(classifierString);
                final PaginatedResult result = qm.getChildrenProjects(classifier, project.getUuid(), true, excludeInactive);
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/{uuid}/children/tag/{tag}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all children for a project by tag",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjectsByTag(
            @ApiParam(value = "The tag to query on", required = true)
            @PathParam("tag") String tagString,
            @ApiParam(value = "The UUID of the project to get the children from", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final Tag tag = qm.getTagByName(tagString);
                final PaginatedResult result = qm.getChildrenProjects(tag, project.getUuid(), true, excludeInactive);
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/withoutDescendantsOf/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all projects without the descendants of the selected project",
            response = Project.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of projects")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsWithoutDescendantsOf(
                                @ApiParam(value = "The UUID of the project which descendants will be excluded", required = true)
                                @PathParam("uuid") String uuid,
                                @ApiParam(value = "The optional name of the project to query on", required = false)
                                @QueryParam("name") String name,
                                @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
                                @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final PaginatedResult result = (name != null) ? qm.getProjectsWithoutDescendantsOf(name, excludeInactive, project) : qm.getProjectsWithoutDescendantsOf(excludeInactive, project);
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else{
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the project could not be found.").build();
            }
        }
    }
}
