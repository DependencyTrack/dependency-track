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
import alpine.model.Team;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
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
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing notification rules.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/notification/rule")
@Tag(name = "notification")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class NotificationRuleResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(NotificationRuleResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all notification rules",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all notification rules",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of notification rules", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = NotificationRule.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getAllNotificationRules() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getNotificationRules();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response createNotificationRule(NotificationRule jsonRule) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRule, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher publisher = null;
            if (jsonRule.getPublisher() != null) {
                publisher =qm.getObjectByUuid(NotificationPublisher.class, jsonRule.getPublisher().getUuid());
            }
            if (publisher == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification publisher could not be found.").build();
            }
            final NotificationRule rule = qm.createNotificationRule(
                    StringUtils.trimToNull(jsonRule.getName()),
                    jsonRule.getScope(),
                    jsonRule.getNotificationLevel(),
                    publisher
            );
            return Response.status(Response.Status.CREATED).entity(rule).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification rule could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateNotificationRule(NotificationRule jsonRule) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRule, "name"),
                validator.validateProperty(jsonRule, "publisherConfig")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, jsonRule.getUuid());
            if (rule != null) {
                jsonRule.setName(StringUtils.trimToNull(jsonRule.getName()));
                rule = qm.updateNotificationRule(jsonRule);
                return Response.ok(rule).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification rule could not be found.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Notification rule removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification rule could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteNotificationRule(NotificationRule jsonRule) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, jsonRule.getUuid());
            if (rule != null) {
                qm.delete(rule);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification rule could not be found.").build();
            }
        }
    }

    @POST
    @Path("/{ruleUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds a project to a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule already has the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response addProjectToRule(
            @Parameter(description = "The UUID of the rule to add a project to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The notification rule could not be found.").build();
            }
            if (rule.getScope() != NotificationScope.PORTFOLIO) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Project limitations are only possible on notification rules with PORTFOLIO scope.").build();
            }
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final List<Project> projects = rule.getProjects();
            if (projects != null && !projects.contains(project)) {
                rule.getProjects().add(project);
                qm.persist(rule);
                return Response.ok(rule).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{ruleUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a project from a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule does not have the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response removeProjectFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The notification rule could not be found.").build();
            }
            if (rule.getScope() != NotificationScope.PORTFOLIO) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Project limitations are only possible on notification rules with PORTFOLIO scope.").build();
            }
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final List<Project> projects = rule.getProjects();
            if (projects != null && projects.contains(project)) {
                rule.getProjects().remove(project);
                qm.persist(rule);
                return Response.ok(rule).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @POST
    @Path("/{ruleUuid}/team/{teamUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds a team to a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule already has the specified team assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification rule or team could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response addTeamToRule(
            @Parameter(description = "The UUID of the rule to add a team to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the team to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The notification rule could not be found.").build();
            }
            if (!rule.getPublisher().getPublisherClass().equals(SendMailPublisher.class.getName())) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Team subscriptions are only possible on notification rules with EMAIL publisher.").build();
            }
            final Team team = qm.getObjectByUuid(Team.class, teamUuid);
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            final List<Team> teams = rule.getTeams();
            if (teams != null && !teams.contains(team)) {
                rule.getTeams().add(team);
                qm.persist(rule);
                return Response.ok(rule).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{ruleUuid}/team/{teamUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a team from a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule does not have the specified team assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification rule or team could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response removeTeamFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The notification rule could not be found.").build();
            }
            if (!rule.getPublisher().getPublisherClass().equals(SendMailPublisher.class.getName())) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Team subscriptions are only possible on notification rules with EMAIL publisher.").build();
            }
            final Team team = qm.getObjectByUuid(Team.class, teamUuid);
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            final List<Team> teams = rule.getTeams();
            if (teams != null && teams.contains(team)) {
                rule.getTeams().remove(team);
                qm.persist(rule);
                return Response.ok(rule).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }
}
