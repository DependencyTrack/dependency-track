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

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.ScheduledNotificationTaskManager;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * JAX-RS resources for processing scheduled notification rules.
 */
@Path("/v1/schedulednotification/rule")
@Tag(name = "schedulednotification")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ScheduledNotificationRuleResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(ScheduledNotificationRuleResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all scheduled notification rules",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all scheduled notification rules",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of scheduled notification rules", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ScheduledNotificationRule.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getAllScheduledNotificationRules() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getScheduledNotificationRules();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response createScheduledNotificationRule(ScheduledNotificationRule jsonRule) {
        final Validator validator = super.getValidator();
        failOnValidationError(
            validator.validateProperty(jsonRule, "name"),
            validator.validateProperty(jsonRule, "cronConfig"),
            validator.validateProperty(jsonRule, "lastExecutionTime")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher publisher = null;
            if (jsonRule.getPublisher() != null) {
                publisher =qm.getObjectByUuid(NotificationPublisher.class, jsonRule.getPublisher().getUuid());
            }
            if (publisher == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification publisher could not be found.").build();
            }
            final ScheduledNotificationRule rule = qm.createScheduledNotificationRule(
                    StringUtils.trimToNull(jsonRule.getName()),
                    jsonRule.getScope(),
                    jsonRule.getNotificationLevel(),
                    publisher
            );
            
            if(rule.isEnabled()) {
                Schedule schedule;
                try {
                    schedule = Schedule.create(jsonRule.getCronConfig());
                    ScheduledNotificationTaskManager.scheduleNextRuleTask(rule.getUuid(), schedule);
                } catch (InvalidExpressionException e) {
                    LOGGER.error("Cron expression is invalid: " + jsonRule.getCronConfig());
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cron expression").build();
                }
            }

            return Response.status(Response.Status.CREATED).entity(rule).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateScheduledNotificationRule(ScheduledNotificationRule jsonRule) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRule, "name"),
                validator.validateProperty(jsonRule, "publisherConfig"),
                validator.validateProperty(jsonRule, "cronConfig"),
                validator.validateProperty(jsonRule, "lastExecutionTime")
        );

        try (QueryManager qm = new QueryManager()) {
            ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, jsonRule.getUuid());
            if (rule != null) {
                jsonRule.setName(StringUtils.trimToNull(jsonRule.getName()));
                rule = qm.updateScheduledNotificationRule(jsonRule);

                try {
                    ScheduledNotificationTaskManager.cancelActiveRuleTask(jsonRule.getUuid());
                    if (rule.isEnabled()) {
                        var schedule = Schedule.create(jsonRule.getCronConfig());
                        ScheduledNotificationTaskManager.scheduleNextRuleTask(jsonRule.getUuid(), schedule);
                    }
                } catch (InvalidExpressionException e) {
                    LOGGER.error("Cron expression is invalid: " + jsonRule.getCronConfig());
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cron expression").build();
                }

                return Response.ok(rule).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the scheduled notification rule could not be found.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "The scheduled notification rule was deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the scheduled notification rule could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteScheduledNotificationRule(ScheduledNotificationRule jsonRule) {
        try (QueryManager qm = new QueryManager()) {
            final ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, jsonRule.getUuid());
            if (rule != null) {
                qm.delete(rule);

                ScheduledNotificationTaskManager.cancelActiveRuleTask(jsonRule.getUuid());
                
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the scheduled notification rule could not be found.").build();
            }
        }
    }

    @POST
    @Path("/{ruleUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds a project to a scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule already has the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The scheduled notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response addProjectToRule(
            @Parameter(description = "The UUID of the rule to add a project to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The scheduled notification rule could not be found.").build();
            }
            if (rule.getScope() != NotificationScope.PORTFOLIO) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Project limitations are only possible on scheduled notification rules with PORTFOLIO scope.").build();
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
            summary = "Removes a project from a scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule does not have the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The scheduled notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response removeProjectFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The scheduled notification rule could not be found.").build();
            }
            if (rule.getScope() != NotificationScope.PORTFOLIO) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Project limitations are only possible on scheduled notification rules with PORTFOLIO scope.").build();
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
            summary = "Adds a team to a scheduled scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule already has the specified team assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The scheduled notification rule or team could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response addTeamToRule(
            @Parameter(description = "The UUID of the rule to add a team to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the team to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (QueryManager qm = new QueryManager()) {
            final ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The scheduled notification rule could not be found.").build();
            }
            if (!rule.getPublisher().getPublisherClass().equals(SendMailPublisher.class.getName())) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Team subscriptions are only possible on scheduled notification rules with EMAIL publisher.").build();
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

    @POST
    @Path("/execute")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Executes a scheduled notification rule instantly ignoring the cron expression",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the scheduled notification rule could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response executeScheduledNotificationRuleNow(ScheduledNotificationRule jsonRule) {
        try (QueryManager qm = new QueryManager()) {
            ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, jsonRule.getUuid());
            if (rule != null) {
                try {
                    ScheduledNotificationTaskManager.cancelActiveRuleTask(rule.getUuid());
                    if (rule.isEnabled()) {
                        // schedule must be passed too, to schedule the next execution according to cron expression again
                        var schedule = Schedule.create(rule.getCronConfig());
                        ScheduledNotificationTaskManager.scheduleNextRuleTask(rule.getUuid(), schedule, 0, TimeUnit.MILLISECONDS);
                    } else {
                        ScheduledNotificationTaskManager.scheduleNextRuleTaskOnce(rule.getUuid(), 0, TimeUnit.MILLISECONDS);
                    }
                } catch (InvalidExpressionException e) {
                    LOGGER.error("Cron expression is invalid: " + rule.getCronConfig());
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cron expression").build();
                }

                return Response.ok(rule).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the scheduled notification rule could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{ruleUuid}/team/{teamUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a team from a scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = ScheduledNotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule does not have the specified team assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The scheduled notification rule or team could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response removeTeamFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (QueryManager qm = new QueryManager()) {
            final ScheduledNotificationRule rule = qm.getObjectByUuid(ScheduledNotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The scheduled notification rule could not be found.").build();
            }
            if (!rule.getPublisher().getPublisherClass().equals(SendMailPublisher.class.getName())) {
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Team subscriptions are only possible on scheduled notification rules with EMAIL publisher.").build();
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
