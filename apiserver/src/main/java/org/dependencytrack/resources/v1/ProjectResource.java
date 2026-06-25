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

import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.validation.Validator;
import jakarta.validation.constraints.Size;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.ProjectAccess;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao.ListProjectsRow;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.jdbi.query.ListProjectsConciseQuery;
import org.dependencytrack.persistence.jdbi.query.ListProjectsQuery;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import org.dependencytrack.resources.v1.vo.ConciseProject;
import org.dependencytrack.resources.v1.vo.ListProjectsResponseItem;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.jdo.FetchGroup;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static java.util.Objects.requireNonNullElse;
import static java.util.Objects.requireNonNullElseGet;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectCreatedNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isPersistent;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/**
 * JAX-RS resources for processing projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/project")
@io.swagger.v3.oas.annotations.tags.Tag(name = "project")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ProjectResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all projects",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all projects",
                    headers = @Header(name = TOTAL_COUNT_HEADER, schema = @Schema(format = "integer"), description = "The total number of projects"),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjects(@Parameter(description = "The optional name of the project to query on")
                                @QueryParam("name") String name,
                                @Parameter(description = "Optionally excludes inactive projects from being returned")
                                @QueryParam("excludeInactive") boolean excludeInactive,
                                @Parameter(description = "Optionally excludes children projects from being returned")
                                @QueryParam("onlyRoot") boolean onlyRoot,
                                @Parameter(description = "The UUID of the team which projects shall be excluded", schema = @Schema(format = "uuid", type = "string"))
                                @QueryParam("notAssignedToTeamWithUuid") @ValidUuid String notAssignedToTeamWithUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            Team notAssignedToTeam;
            if (StringUtils.isNotEmpty(notAssignedToTeamWithUuid)) {
                notAssignedToTeam = qm.getObjectByUuid(Team.class, notAssignedToTeamWithUuid);
                if (notAssignedToTeam == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
                }
            }
            final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                    getAlpineRequest(),
                    handle -> handle.attach(ProjectDao.class).getProjects(
                            new ListProjectsQuery()
                                    .withNameFilter(name)
                                    .withNotAssignedToTeamWithUuidFilter(notAssignedToTeamWithUuid)
                                    .withSearchText(getAlpineRequest().getFilter())
                                    .withExcludeInactive(excludeInactive)
                                    .withOnlyRoot(onlyRoot)
                                    .withIncludeMetrics(true)));
            return Response
                    .ok(ListProjectsResponseItem.of(projectsPage.items()))
                    .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                    .build();
        }
    }

    @GET
    @Path("/concise")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all projects, in a concise representation.",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all projects in concise representation",
                    headers = @Header(name = TOTAL_COUNT_HEADER, schema = @Schema(format = "integer"), description = "The total number of projects"),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConciseProject.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsConcise(
            @Parameter(description = "Name to filter on. Must be exact match.")
            @QueryParam("name") final String nameFilter,
            @Parameter(description = "Version to filter on. Must be exact match.")
            @QueryParam("version") final String versionFilter,
            @Parameter(description = "Classifier to filter on. Must be exact match.")
            @QueryParam("classifier") final String classifierFilter,
            @Parameter(description = "Tag to filter on. Must be exact match.")
            @QueryParam("tag") final String tagFilter,
            @Parameter(description = "Team to filter on. Must be exact match.")
            @QueryParam("team") final String teamFilter,
            @Parameter(description = "Whether to show only active, or only inactive projects.")
            @QueryParam("active") final Boolean activeFilter,
            @Parameter(description = "Whether to show only root projects, i.e. those without a parent.")
            @QueryParam("onlyRoot") final Boolean onlyRootFilter,
            @Parameter(description = "Whether to include metrics in the response.")
            @QueryParam("includeMetrics") final boolean includeMetrics
    ) {
        final Page<ProjectDao.ConciseProjectListRow> page = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle
                        .attach(ProjectDao.class)
                        .getPageConcise(new ListProjectsConciseQuery()
                                .withNameFilter(nameFilter)
                                .withVersionFilter(versionFilter)
                                .withClassifierFilter(classifierFilter)
                                .withTagFilter(tagFilter)
                                .withTeamFilter(teamFilter)
                                .withActiveFilter(activeFilter)
                                .withOnlyRootFilter(onlyRootFilter)
                                .withSearchText(getAlpineRequest().getFilter())
                                .withIncludeMetrics(includeMetrics)));

        final List<ConciseProject> projects = page.items().stream().map(ConciseProject::new).toList();
        return Response.ok(projects).header(TOTAL_COUNT_HEADER, page.totalCount().value()).build();
    }

    @GET
    @Path("/concise/{uuid}/children")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of a given project's children, in a concise representation.",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all child projects in a concise representation",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of child projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConciseProject.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectChildrenConcise(
            @Parameter(description = "UUID of the project", required = true)
            @PathParam("uuid") final String parentUuid,
            @Parameter(description = "Name to filter on. Must be exact match.")
            @QueryParam("name") final String nameFilter,
            @Parameter(description = "Version to filter on. Must be exact match.")
            @QueryParam("version") final String versionFilter,
            @Parameter(description = "Classifier to filter on. Must be exact match.")
            @QueryParam("classifier") final String classifierFilter,
            @Parameter(description = "Tag to filter on. Must be exact match.")
            @QueryParam("tag") final String tagFilter,
            @Parameter(description = "Team to filter on. Must be exact match.")
            @QueryParam("team") final String teamFilter,
            @Parameter(description = "Whether to show only active, or only inactive projects. Omitting the filter will show both.")
            @QueryParam("active") final Boolean activeFilter,
            @Parameter(description = "Whether to include metrics in the response.")
            @QueryParam("includeMetrics") final boolean includeMetrics
    ) {
        final Page<ProjectDao.ConciseProjectListRow> page = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle
                        .attach(ProjectDao.class)
                        .getPageConcise(new ListProjectsConciseQuery()
                                .withNameFilter(nameFilter)
                                .withVersionFilter(versionFilter)
                                .withClassifierFilter(classifierFilter)
                                .withTagFilter(tagFilter)
                                .withTeamFilter(teamFilter)
                                .withActiveFilter(activeFilter)
                                .withParentUuidFilter(UUID.fromString(parentUuid))
                                .withSearchText(getAlpineRequest().getFilter())
                                .withIncludeMetrics(includeMetrics)));

        final List<ConciseProject> projects = page.items().stream().map(ConciseProject::new).toList();
        return Response.ok(projects).header(TOTAL_COUNT_HEADER, page.totalCount().value()).build();
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific project",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProject(
            @Parameter(description = "The UUID of the project to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getProject(uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);

            final boolean isParentAccessible =
                    project.getParent() != null
                            && qm.hasAccess(getPrincipal(), project.getParent());

            qm.makeTransient(project);
            if (!isParentAccessible) {
                project.setParent(null);
            }

            return Response.ok(project).build();
        }
    }

    @GET
    @Path("/latest/{name}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the latest version of a project by its name",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The latest version of the specified project",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getLatestProjectByName(
            @Parameter(description = "The name of the project to retrieve the latest version of", required = true)
            @PathParam("name") String name) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(name));
            if (project != null) {
                requireAccess(qm, project);
                project.setMetrics(
                        withJdbiHandle(handle -> handle
                                .attach(MetricsDao.class)
                                .getMostRecentProjectMetrics(project.getId())));
                project.setVersions(qm.getProjectVersions(project));
                return Response.ok(project).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/lookup")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific project by its name and version",
            operationId = "getProjectByNameAndVersion",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific project by its name and version",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProject(
            @Parameter(description = "The name of the project to query on", required = true)
            @QueryParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @QueryParam("version") String version) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = ProjectAccess.unrestricted(() -> qm.getProject(name, version));
            if (project != null) {
                requireAccess(qm, project);
                project.setMetrics(
                        withJdbiHandle(handle -> handle
                                .attach(MetricsDao.class)
                                .getMostRecentProjectMetrics(project.getId())));
                project.setVersions(qm.getProjectVersions(project));
                return Response.ok(project).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/tag/{tag}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all projects by tag",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all projects by tag",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsByTag(
            @Parameter(description = "The tag to query on", required = true)
            @PathParam("tag") String tagString,
            @Parameter(description = "Optionally excludes inactive projects from being returned")
            @QueryParam("excludeInactive") boolean excludeInactive,
            @Parameter(description = "Optionally excludes children projects from being returned")
            @QueryParam("onlyRoot") boolean onlyRoot) {
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(ProjectDao.class).getProjects(
                        new ListProjectsQuery()
                                .withTagFilter(tagString)
                                .withSearchText(getAlpineRequest().getFilter())
                                .withExcludeInactive(excludeInactive)
                                .withOnlyRoot(onlyRoot)
                                .withIncludeMetrics(true)));
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

    @GET
    @Path("/classifier/{classifier}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all projects by classifier",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all projects by classifier",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsByClassifier(
            @Parameter(description = "The classifier to query on", required = true)
            @PathParam("classifier") Classifier classifier,
            @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive,
            @Parameter(description = "Optionally excludes children projects from being returned", required = false)
            @QueryParam("onlyRoot") boolean onlyRoot) {
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(ProjectDao.class).getProjects(
                        new ListProjectsQuery()
                                .withClassifierFilter(classifier.name())
                                .withSearchText(getAlpineRequest().getFilter())
                                .withExcludeInactive(excludeInactive)
                                .withOnlyRoot(onlyRoot)
                                .withIncludeMetrics(true)));
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new project",
            description = """
                    <p>
                      To create the project under a parent, set <code>parent</code> to an object
                      containing the parent's <code>uuid</code>. To create a top-level project,
                      omit <code>parent</code> or set it to <code>null</code>. Providing
                      <code>parent</code> without a non-null <code>uuid</code> is rejected with 400.
                    </p>
                    <p>
                      When portfolio access control is enabled, one or more teams to grant access
                      to can be provided via <code>accessTeams</code>. Either <code>uuid</code> or
                      <code>name</code> of a team must be specified. Only teams which the authenticated
                      principal is a member of can be assigned. Principals with <strong>ACCESS_MANAGEMENT</strong>
                      permission can assign <em>any</em> team.
                    </p>
                    <p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created project",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "400", description = "Bad Request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the provided parent project, or previous latest project version, is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "409", description = """
                    <ul>
                      <li>An inactive Parent cannot be selected as parent, or</li>
                      <li>A project with the specified name already exists</li>
                    </ul>""")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE})
    public Response createProject(final Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "authors"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "collectionLogic"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId"),
                validator.validateProperty(jsonProject, "accessTeams")
        );
        if (jsonProject.getCollectionLogic() != null) {
            jsonProject.setClassifier(null);
        } else if (jsonProject.getClassifier() == null) {
            jsonProject.setClassifier(Classifier.APPLICATION);
        }
        try (final var qm = new QueryManager(getAlpineRequest())) {
            if (jsonProject.isLatest()) {
                final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(jsonProject.getName()));
                if (oldLatest != null) {
                    requireAccess(qm, oldLatest);
                }
            }
            final Project createdProject = qm.callInTransaction(() -> {
                if (jsonProject.getParent() != null) {
                    final UUID parentUuid = jsonProject.getParent().getUuid();
                    if (parentUuid == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("parent.uuid must be provided when parent is set")
                                .build());
                    }
                    final Project parent = qm.getObjectByUuid(Project.class, parentUuid);
                    if (parent == null) {
                        throw new NoSuchElementException("Parent project could not be found");
                    }
                    requireAccess(qm, parent, "Access to the requested parent project is forbidden");
                    jsonProject.setParent(parent);
                }

                Principal principal = getPrincipal();

                final Set<Team> chosenTeams = requireNonNullElseGet(
                        jsonProject.getAccessTeams(), Collections::emptySet);
                jsonProject.setAccessTeams(null);

                for (final Team chosenTeam : chosenTeams) {
                    if (chosenTeam.getUuid() == null && chosenTeam.getName() == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("""
                                        accessTeams must either specify a UUID or a name,\
                                        but the team %s has neither.\
                                        """.formatted(chosenTeam))
                                .build());
                    }
                }

                if (!chosenTeams.isEmpty()) {
                    List<Team> userTeams;
                    if (principal instanceof final User user) {
                        userTeams = user.getTeams();
                    } else if (principal instanceof final ApiKey apiKey) {
                        userTeams = apiKey.getTeams();
                    } else {
                        userTeams = List.of();
                    }

                    boolean canSeeAllTeams =
                            super.hasPermission(Permissions.Constants.ACCESS_MANAGEMENT)
                                    || super.hasPermission(Permissions.Constants.ACCESS_MANAGEMENT_READ);
                    List<Team> visibleTeams = canSeeAllTeams ? qm.getTeams().getList(Team.class) : userTeams;
                    final var visibleTeamByUuid = new HashMap<UUID, Team>(visibleTeams.size());
                    final var visibleTeamByName = new HashMap<String, Team>(visibleTeams.size());
                    for (final Team visibleTeam : visibleTeams) {
                        visibleTeamByUuid.put(visibleTeam.getUuid(), visibleTeam);
                        visibleTeamByName.put(visibleTeam.getName(), visibleTeam);
                    }

                    for (Team chosenTeam : chosenTeams) {
                        Team visibleTeam = visibleTeamByUuid.getOrDefault(
                                chosenTeam.getUuid(),
                                visibleTeamByName.get(chosenTeam.getName()));
                        if (visibleTeam == null) {
                            throw new ClientErrorException(Response
                                    .status(Response.Status.BAD_REQUEST)
                                    .entity("""
                                            The team with %s can not be assigned because it does not exist, \
                                            or is not accessible to the authenticated principal.\
                                            """.formatted(chosenTeam.getUuid() != null
                                            ? "UUID " + chosenTeam.getUuid()
                                            : "name " + chosenTeam.getName()))
                                    .build());
                        }
                        if (!isPersistent(visibleTeam)) {
                            // Teams sourced from the principal will not be in persistent state
                            // and need to be attached to the persistence context.
                            visibleTeam = qm.getObjectById(Team.class, visibleTeam.getId());
                        }
                        jsonProject.addAccessTeam(visibleTeam);
                    }
                }

                final Project project;
                try {
                    project = qm.createProject(jsonProject, jsonProject.getTags(), true);
                } catch (IllegalArgumentException e) {
                    LOGGER.debug("Failed to create project %s".formatted(jsonProject), e);
                    throw new ClientErrorException(Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity(e.getMessage())
                            .build());
                } catch (RuntimeException e) {
                    if (isUniqueConstraintViolation(e)) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.CONFLICT)
                                .entity("A project with the specified name already exists.")
                                .build());
                    }

                    LOGGER.error("Failed to create project %s".formatted(jsonProject), e);
                    throw new ServerErrorException(Response.Status.INTERNAL_SERVER_ERROR);
                }

                qm.updateNewProjectACL(project, principal);

                new JdoNotificationEmitter(qm).emit(
                        createProjectCreatedNotification(
                                NotificationModelConverter.convert(project)));

                return project;
            });

            try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, createdProject.getUuid().toString());
                 var _ = MDC.putCloseable(MDC_PROJECT_NAME, createdProject.getName());
                 var _ = MDC.putCloseable(MDC_PROJECT_VERSION, createdProject.getVersion())) {

                LOGGER.info("Project {} created by {}", createdProject, super.getPrincipal().getName());
            }
            return Response.status(Response.Status.CREATED).entity(createdProject).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a project",
            description = """
                    <p>
                      To re-parent the project, set <code>parent</code> to an object containing
                      the new parent's <code>uuid</code>. Omit <code>parent</code> (or set it to
                      <code>null</code>) to leave the parent unchanged. Providing <code>parent</code>
                      without a non-null <code>uuid</code> is rejected with 400.
                    </p>
                    <p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated project",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "400", description = "Bad Request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the project, the provided parent, or the previous latest project version, is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found"),
            @ApiResponse(responseCode = "409", description = """
                    <ul>
                      <li>An inactive Parent cannot be selected as parent, or</li>
                      <li>Project cannot be set to inactive if active children are present, or</li>
                      <li>A project with the specified name already exists, or</li>
                      <li>A project cannot select itself as a parent</li>
                    </ul>""")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response updateProject(Project jsonProject) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "authors"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                validator.validateProperty(jsonProject, "name"),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "collectionLogic"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId")
        );
        if (jsonProject.getCollectionLogic() != null) {
            jsonProject.setClassifier(null);
        } else if (jsonProject.getClassifier() == null) {
            jsonProject.setClassifier(Classifier.APPLICATION);
        }
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project updatedProject = qm.callInTransaction(() -> {
                Project project = qm.getObjectByUuid(Project.class, jsonProject.getUuid());
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the project could not be found.")
                            .build());
                }
                requireAccess(qm, project);

                if (jsonProject.getParent() != null) {
                    final UUID parentUuid = jsonProject.getParent().getUuid();
                    if (parentUuid == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("parent.uuid must be provided when parent is set")
                                .build());
                    }
                    final Project parent = qm.getObjectByUuid(Project.class, parentUuid);
                    if (parent == null) {
                        throw new NoSuchElementException("Parent project could not be found");
                    }
                    requireAccess(qm, parent, "Access to the requested parent project is forbidden");
                    jsonProject.setParent(parent);
                }

                final String name = StringUtils.trimToNull(jsonProject.getName());
                // Name cannot be empty or null - prevent it
                if (name == null) {
                    jsonProject.setName(project.getName());
                }
                // if project is newly set to latest, ensure user has access to current latest version to modify it
                if (jsonProject.isLatest() && !project.isLatest()) {
                    final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(name));
                    if (oldLatest != null) {
                        requireAccess(qm, oldLatest);
                    }
                }

                if (jsonProject.getCollectionLogic() == ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG
                        && jsonProject.getCollectionTag() == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("A collection tag must be specified for AGGREGATE_DIRECT_CHILDREN_WITH_TAG logic.")
                            .build());
                }

                try {
                    return qm.updateProject(jsonProject, true);
                } catch (IllegalArgumentException e) {
                    LOGGER.debug("Failed to update project %s".formatted(jsonProject.getUuid()), e);
                    throw new ClientErrorException(Response
                            .status(Response.Status.CONFLICT)
                            .entity(e.getMessage())
                            .build());
                }
            });

            try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, updatedProject.getUuid().toString());
                 var _ = MDC.putCloseable(MDC_PROJECT_NAME, updatedProject.getName());
                 var _ = MDC.putCloseable(MDC_PROJECT_VERSION, updatedProject.getVersion())) {

                LOGGER.info("Project {} updated by {}", updatedProject, super.getPrincipal().getName());
            }
            return Response.ok(updatedProject).build();
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new ClientErrorException(Response
                        .status(Response.Status.CONFLICT)
                        .entity("A project with the specified name and version already exists.")
                        .build());
            }
            throw e;
        }
    }

    @PATCH
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Partially updates a project",
            description = """
                    <p>
                      To re-parent the project, set <code>parent</code> to an object containing
                      the new parent's <code>uuid</code>. Omit <code>parent</code> (or set it to
                      <code>null</code>) to leave the parent unchanged. Providing <code>parent</code>
                      without a non-null <code>uuid</code> is rejected with 400.
                    </p>
                    <p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated project",
                    content = @Content(schema = @Schema(implementation = Project.class))
            ),
            @ApiResponse(responseCode = "400", description = "Bad Request"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project, the provided parent, or the previous latest project version, is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found"),
            @ApiResponse(responseCode = "409", description = """
                    <ul>
                      <li>An inactive Parent cannot be selected as parent, or</li>
                      <li>Project cannot be set to inactive if active children are present, or</li>
                      <li>A project with the specified name already exists, or</li>
                      <li>A project cannot select itself as a parent</li>
                    </ul>""")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response patchProject(
            @Parameter(description = "The UUID of the project to modify", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            Project jsonProject) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(jsonProject, "authors"),
                validator.validateProperty(jsonProject, "publisher"),
                validator.validateProperty(jsonProject, "group"),
                jsonProject.getName() != null ? validator.validateProperty(jsonProject, "name") : Set.of(),
                validator.validateProperty(jsonProject, "description"),
                validator.validateProperty(jsonProject, "version"),
                validator.validateProperty(jsonProject, "classifier"),
                validator.validateProperty(jsonProject, "collectionLogic"),
                validator.validateProperty(jsonProject, "cpe"),
                validator.validateProperty(jsonProject, "purl"),
                validator.validateProperty(jsonProject, "swidTagId")
        );

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project updatedProject = qm.callInTransaction(() -> {
                Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the project could not be found.")
                            .build());
                }
                requireAccess(qm, project);
                // if project is newly set to latest, ensure user has access to current latest version to modify it
                if (jsonProject.isLatest() && !project.isLatest()) {
                    final var oldName = jsonProject.getName() != null ? jsonProject.getName() : project.getName();
                    final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(oldName));
                    if (oldLatest != null) {
                        requireAccess(qm, oldLatest);
                    }
                }

                var modified = false;
                project = qm.detachWithGroups(project, List.of(FetchGroup.DEFAULT, Project.FetchGroup.PARENT.name()));
                modified |= setIfDifferent(jsonProject, project, Project::getName, Project::setName);
                modified |= setIfDifferent(jsonProject, project, Project::getVersion, Project::setVersion);
                modified |= setIfDifferent(jsonProject, project, Project::getAuthors, Project::setAuthors);
                modified |= setIfDifferent(jsonProject, project, Project::getPublisher, Project::setPublisher);
                modified |= setIfDifferent(jsonProject, project, Project::getGroup, Project::setGroup);
                modified |= setIfDifferent(jsonProject, project, Project::getDescription, Project::setDescription);
                modified |= setIfDifferent(jsonProject, project, Project::getClassifier, Project::setClassifier);
                modified |= setIfDifferent(jsonProject, project, Project::getCollectionLogic, Project::setCollectionLogic);
                modified |= setIfDifferent(jsonProject, project, Project::getCollectionTag, Project::setCollectionTag);
                modified |= setIfDifferent(jsonProject, project, Project::getCpe, Project::setCpe);
                modified |= setIfDifferent(jsonProject, project, Project::getPurl, Project::setPurl);
                modified |= setIfDifferent(jsonProject, project, Project::getSwidTagId, Project::setSwidTagId);
                modified |= setIfDifferent(jsonProject, project, Project::getManufacturer, Project::setManufacturer);
                modified |= setIfDifferent(jsonProject, project, Project::getSupplier, Project::setSupplier);
                modified |= setIfDifferent(jsonProject, project, Project::isLatest, Project::setIsLatest);
                modified |= setIfDifferent(jsonProject, project, Project::isActive, Project::setActive);
                if (project.getCollectionLogic() != null && project.getClassifier() != null) {
                    project.setClassifier(null);
                    modified = true;
                }
                if (jsonProject.getParent() != null) {
                    final UUID parentUuid = jsonProject.getParent().getUuid();
                    if (parentUuid == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("parent.uuid must be provided when parent is set")
                                .build());
                    }
                    final Project parent = qm.getObjectByUuid(Project.class, parentUuid);
                    if (parent == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The UUID of the parent project could not be found.")
                                .build());
                    }
                    requireAccess(qm, parent, "Access to the requested parent project is forbidden");
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

                if (!modified) {
                    return null;
                }

                if (project.getCollectionLogic() == ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG
                        && project.getCollectionTag() == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("A collection tag must be specified for AGGREGATE_DIRECT_CHILDREN_WITH_TAG logic.")
                            .build());
                }

                try {
                    return qm.updateProject(project, true);
                } catch (IllegalArgumentException e) {
                    LOGGER.debug("Failed to patch project %s".formatted(uuid));
                    throw new ClientErrorException(Response
                            .status(Response.Status.CONFLICT)
                            .entity(e.getMessage())
                            .build());
                }
            });

            if (updatedProject == null) {
                return Response.notModified().build();
            }

            try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, updatedProject.getUuid().toString());
                 var _ = MDC.putCloseable(MDC_PROJECT_NAME, updatedProject.getName());
                 var _ = MDC.putCloseable(MDC_PROJECT_VERSION, updatedProject.getVersion())) {

                LOGGER.info("Project {} updated by {}", updatedProject, super.getPrincipal().getName());
            }
            return Response.ok(updatedProject).build();
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new ClientErrorException(Response
                        .status(Response.Status.CONFLICT)
                        .entity("A project with the specified name and version already exists.")
                        .build());
            }
            throw e;
        }
    }

    /**
     * returns `true` if the given [updated] collection should be considered an update of the [original] collection.
     */
    private static <T> boolean isCollectionModified(Collection<T> updated, Collection<T> original) {
        return updated != null && (!updated.isEmpty() || !requireNonNullElse(original, Collections.emptyList()).isEmpty());
    }

    /**
     * updates the given target object using the supplied setter method with the
     * new value from the source object using the supplied getter method. But
     * only if the new value is not {@code null} and it is not
     * {@link Object#equals(java.lang.Object) equal to} the old value.
     *
     * @param <T>    the type of the old and new value
     * @param source the source object that contains the new value
     * @param target the target object that should be updated
     * @param getter the method to retrieve the new value from {@code source}
     *               and the old value from {@code target}
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
    @Operation(
            summary = "Deletes a project",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Project removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found"),
            @ApiResponse(responseCode = "500", description = "Unable to delete components of the project")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteProject(
            @Parameter(description = "The UUID of the project to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.runInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the project could not be found.")
                            .build());
                }
                requireAccess(qm, project);

                try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, project.getUuid().toString());
                     var _ = MDC.putCloseable(MDC_PROJECT_NAME, project.getName());
                     var _ = MDC.putCloseable(MDC_PROJECT_VERSION, project.getVersion())) {
                    LOGGER.info("Project {} deletion request by {}", project, super.getPrincipal().getName());
                }

                qm.delete(project);
            });
        }

        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @POST
    @Path("/batchDelete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a list of projects specified by their UUIDs",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Projects removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE
    })
    public Response deleteProjects(@Size(min = 1, max = 1000) final Set<UUID> uuids) {
        final Set<UUID> deletedProjectUuids = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(ProjectDao.class).deleteProjects(uuids));
        for (final UUID uuid : deletedProjectUuids) {
            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted project {}", uuid);
        }
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @PUT
    @Path("/clone")
    @Deprecated(since = "5.0.0")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Clones a project",
            description = """
                    <p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>
                    <p><strong>Deprecated</strong>! Use <code>/api/v2/projects/{uuid}/clone</code> instead.</p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking cloning progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project, or the previous latest project version, is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE})
    public Response cloneProject(CloneProjectRequest jsonRequest) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRequest, "project"),
                validator.validateProperty(jsonRequest, "version")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.runInTransaction(() -> {
                final Project sourceProject = qm.getObjectByUuid(Project.class, jsonRequest.getProject(), Project.FetchGroup.ALL.name());
                if (sourceProject == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the project could not be found.")
                            .build());
                }
                requireAccess(qm, sourceProject);
                if (qm.doesProjectExist(sourceProject.getName(), StringUtils.trimToNull(jsonRequest.getVersion()))) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.CONFLICT)
                            .entity("A project with the specified name and version already exists.")
                            .build());
                }
                // if project is newly set to latest, ensure user has access to current latest version to modify it
                if (jsonRequest.makeCloneLatest() && !sourceProject.isLatest()) {
                    final Project oldLatest = ProjectAccess.unrestricted(() -> qm.getLatestProjectVersion(sourceProject.getName()));
                    if (oldLatest != null) {
                        requireAccess(qm, oldLatest);
                    }
                }

                try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, sourceProject.getUuid().toString());
                     var _ = MDC.putCloseable(MDC_PROJECT_NAME, sourceProject.getName());
                     var _ = MDC.putCloseable(MDC_PROJECT_VERSION, sourceProject.getVersion())) {

                    LOGGER.info("Project {} is being cloned by {}", sourceProject, super.getPrincipal().getName());
                }
            });

            final UUID sourceProjectUuid = UUID.fromString(jsonRequest.getProject());
            inJdbiTransaction(handle -> {
                final UUID clonedProjectUuid = handle.attach(ProjectDao.class).cloneProject(
                        new CloneProjectCommand(
                                sourceProjectUuid,
                                jsonRequest.getVersion(),
                                jsonRequest.makeCloneLatest(),
                                jsonRequest.includeACL(),
                                jsonRequest.includeComponents(),
                                // NB: For legacy reasons, includeAuditHistory implies includeFindings.
                                /* includeFindings */ jsonRequest.includeAuditHistory(),
                                /* includeFindingsAuditHistory */ jsonRequest.includeAuditHistory(),
                                // NB: For legacy reasons, includePolicyViolations implies includePolicyViolationsAuditHistory.
                                jsonRequest.includePolicyViolations(),
                                /* includePolicyViolationsAuditHistory */ jsonRequest.includePolicyViolations(),
                                jsonRequest.includeProperties(),
                                jsonRequest.includeServices(),
                                jsonRequest.includeTags()));
                handle.attach(MetricsDao.class).updateProjectMetrics(clonedProjectUuid);
                return clonedProjectUuid;
            });

            // NB: For legacy reasons, we still return an event token.
            // At the time when clients get this, the clone has already succeeded.
            return Response.accepted(Map.of("token", UUID.randomUUID())).build();
        }
    }


    @GET
    @Path("/{uuid}/children")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all children for a project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all children for a project",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjects(@Parameter(description = "The UUID of the project to get the children from", schema = @Schema(type = "string", format = "uuid"), required = true)
                                        @PathParam("uuid") @ValidUuid String uuid,
                                        @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
                                        @QueryParam("excludeInactive") boolean excludeInactive) {
        final UUID parentUuid = UUID.fromString(uuid);
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> {
                    requireProjectAccess(handle, parentUuid);
                    return handle.attach(ProjectDao.class).getProjects(
                            new ListProjectsQuery()
                                    .withParentUuidFilter(parentUuid)
                                    .withSearchText(getAlpineRequest().getFilter())
                                    .withExcludeInactive(excludeInactive)
                                    .withIncludeMetrics(true));
                });
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

    @GET
    @Path("/{uuid}/children/classifier/{classifier}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all children for a project by classifier",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all children for a project by classifier",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjectsByClassifier(
            @Parameter(description = "The classifier to query on", required = true)
            @PathParam("classifier") Classifier classifier,
            @Parameter(description = "The UUID of the project to get the children from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive) {
        final UUID parentUuid = UUID.fromString(uuid);
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> {
                    requireProjectAccess(handle, parentUuid);
                    return handle.attach(ProjectDao.class).getProjects(
                            new ListProjectsQuery()
                                    .withClassifierFilter(classifier.name())
                                    .withParentUuidFilter(parentUuid)
                                    .withSearchText(getAlpineRequest().getFilter())
                                    .withExcludeInactive(excludeInactive)
                                    .withIncludeMetrics(true));
                });
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

    @GET
    @Path("/{uuid}/children/tag/{tag}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all children for a project by tag",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all children for a project by tag",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getChildrenProjectsByTag(
            @Parameter(description = "The tag to query on", required = true)
            @PathParam("tag") String tagString,
            @Parameter(description = "The UUID of the project to get the children from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive) {
        final UUID parentUuid = UUID.fromString(uuid);
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> {
                    requireProjectAccess(handle, parentUuid);
                    return handle.attach(ProjectDao.class).getProjects(
                            new ListProjectsQuery()
                                    .withTagFilter(tagString)
                                    .withParentUuidFilter(parentUuid)
                                    .withSearchText(getAlpineRequest().getFilter())
                                    .withExcludeInactive(excludeInactive)
                                    .withIncludeMetrics(true));
                });
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

    @GET
    @Path("/withoutDescendantsOf/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all projects without the descendants of the selected project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all projects without the descendants of the selected project",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ListProjectsResponseItem.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectsWithoutDescendantsOf(
            @Parameter(description = "The UUID of the project which descendants will be excluded", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The optional name of the project to query on", required = false)
            @QueryParam("name") String name,
            @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
            @QueryParam("excludeInactive") boolean excludeInactive) {
        final UUID rootUuid = UUID.fromString(uuid);
        final Page<ListProjectsRow> projectsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> {
                    requireProjectAccess(handle, rootUuid);
                    return handle.attach(ProjectDao.class).getProjects(
                            new ListProjectsQuery()
                                    .withNameFilter(name)
                                    .withExcludeDescendantsOfUuid(rootUuid)
                                    .withSearchText(getAlpineRequest().getFilter())
                                    .withExcludeInactive(excludeInactive)
                                    .withIncludeMetrics(true));
                });
        return Response
                .ok(ListProjectsResponseItem.of(projectsPage.items()))
                .header(TOTAL_COUNT_HEADER, projectsPage.totalCount().value())
                .build();
    }

}
