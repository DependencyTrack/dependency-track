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

import alpine.model.Team;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import com.fasterxml.jackson.databind.JsonNode;
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
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.NotificationFilterExpressionEnv;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.InvalidNotificationFilterExpressionProblemDetails;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.CreateNotificationRuleRequest;
import org.dependencytrack.resources.v1.vo.CreateScheduledNotificationRuleRequest;
import org.dependencytrack.resources.v1.vo.UpdateNotificationRuleRequest;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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
public class NotificationRuleResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRuleResource.class);

    private final PluginManager pluginManager;
    private final RuntimeConfigMapper configMapper;

    @Inject
    NotificationRuleResource(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
        this.configMapper = RuntimeConfigMapper.getInstance();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of all notification rules",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
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
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getAllNotificationRules(
            @Parameter(description = "The notification trigger type to filter on")
            @QueryParam("triggerType") final NotificationTriggerType triggerTypeFilter) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getNotificationRules(triggerTypeFilter);
            final List<NotificationRule> rules = result.getList(NotificationRule.class);

            qm.makeTransientAll(rules);

            final Set<UUID> accessibleProjectUuids =
                    filterAccessibleProjects(
                            rules.stream()
                                    .map(NotificationRule::getProjects)
                                    .filter(Objects::nonNull)
                                    .flatMap(List::stream)
                                    .toList())
                            .stream()
                            .map(Project::getUuid)
                            .collect(Collectors.toSet());
            for (final NotificationRule rule : rules) {
                final List<Project> projects = rule.getProjects();
                if (projects == null) {
                    rule.setProjects(List.of());
                    continue;
                }

                rule.setProjects(projects.stream()
                        .filter(project -> accessibleProjectUuids.contains(project.getUuid()))
                        .toList());
            }

            return Response.ok(rules).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
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
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createNotificationRule(@Valid CreateNotificationRuleRequest request) {
        final NotificationRule createdRule;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            createdRule = qm.callInTransaction(() -> {
                NotificationPublisher publisher = null;
                if (request.publisher() != null) {
                    publisher = qm.getObjectByUuid(NotificationPublisher.class, request.publisher().uuid());
                }
                if (publisher == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the notification publisher could not be found.")
                            .build());
                }

                final NotificationPublisherFactory extensionFactory = pluginManager.getFactory(
                        org.dependencytrack.notification.api.publishing.NotificationPublisher.class,
                        publisher.getExtensionName());

                final NotificationRule rule = qm.createNotificationRule(
                        request.name(),
                        request.scope(),
                        request.level(),
                        publisher);

                final RuntimeConfigSpec ruleConfigSpec = extensionFactory.ruleConfigSpec();
                if (ruleConfigSpec != null) {
                    final String defaultRuleConfigJson =
                            RuntimeConfigMapper.getInstance()
                                    .serialize(ruleConfigSpec.defaultConfig());
                    rule.setPublisherConfig(defaultRuleConfigJson);
                }

                return rule;
            });
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created notification rule '{}'", createdRule.getName());

        return Response
                .status(Response.Status.CREATED)
                .entity(createdRule)
                .build();
    }

    @PUT
    @Path("/scheduled")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new scheduled notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created scheduled notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createScheduledNotificationRule(@Valid CreateScheduledNotificationRuleRequest request) {
        final NotificationRule createdRule;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            createdRule = qm.callInTransaction(() -> {
                NotificationPublisher publisher = null;
                if (request.publisher() != null) {
                    publisher = qm.getObjectByUuid(NotificationPublisher.class, request.publisher().uuid());
                }
                if (publisher == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the notification publisher could not be found.")
                            .build());
                }

                final NotificationPublisherFactory extensionFactory = pluginManager.getFactory(
                        org.dependencytrack.notification.api.publishing.NotificationPublisher.class,
                        publisher.getExtensionName());

                final NotificationRule rule = qm.createScheduledNotificationRule(
                        request.name(),
                        request.scope(),
                        request.level(),
                        publisher);

                final RuntimeConfigSpec ruleConfigSpec = extensionFactory.ruleConfigSpec();
                if (ruleConfigSpec != null) {
                    final String defaultRuleConfigJson =
                            RuntimeConfigMapper.getInstance()
                                    .serialize(ruleConfigSpec.defaultConfig());
                    rule.setPublisherConfig(defaultRuleConfigJson);
                }

                return rule;
            });
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created scheduled notification rule '{}'", createdRule.getName());

        return Response
                .status(Response.Status.CREATED)
                .entity(createdRule)
                .build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid filter expression",
                    content = @Content(
                            schema = @Schema(implementation = InvalidNotificationFilterExpressionProblemDetails.class),
                            mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification rule could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateNotificationRule(@Valid UpdateNotificationRuleRequest request) {
        if (request.filterExpression() != null && !request.filterExpression().isBlank()) {
            NotificationFilterExpressionEnv.getInstance().compile(request.filterExpression());
        }

        final NotificationRule updatedRule;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final NotificationRule persisted = qm.callInTransaction(() -> {
                var rule = qm.getObjectByUuid(NotificationRule.class, request.uuid());
                if (rule == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the notification rule could not be found.")
                            .build());
                }

                final NotificationPublisherFactory publisherFactory = pluginManager.getFactory(
                        org.dependencytrack.notification.api.publishing.NotificationPublisher.class,
                        rule.getPublisher().getExtensionName());

                final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
                if (ruleConfigSpec == null) {
                    if (request.publisherConfig() != null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("The publisher does not support configuration.")
                                .build());
                    }
                } else {
                    if (request.publisherConfig() == null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("The publisher requires configuration, but none was provided.")
                                .build());
                    }

                    try {
                        final JsonNode ruleConfigNode = configMapper.validateJson(request.publisherConfig(), ruleConfigSpec);
                        final RuntimeConfig ruleConfig = configMapper.convert(ruleConfigNode, ruleConfigSpec.configClass());
                        if (ruleConfigSpec.validator() != null) {
                            ruleConfigSpec.validator().validate(ruleConfig);
                        }
                    } catch (InvalidRuntimeConfigException e) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("Invalid publisher configuration: " + e.getMessage())
                                .build());
                    }
                }

                final var transientRule = new NotificationRule();
                transientRule.setName(request.name());
                transientRule.setEnabled(request.enabled());
                transientRule.setNotifyChildren(request.notifyChildren());
                transientRule.setLogSuccessfulPublish(request.logSuccessfulPublish());
                transientRule.setScope(request.scope());
                transientRule.setNotificationLevel(request.level());
                transientRule.setNotifyOn(request.notifyOn());
                transientRule.setPublisherConfig(request.publisherConfig());
                transientRule.setFilterExpression(request.filterExpression());
                transientRule.setTags(request.tags());
                transientRule.setUuid(rule.getUuid());
                transientRule.setTriggerType(rule.getTriggerType());
                if (transientRule.getTriggerType() == NotificationTriggerType.SCHEDULE) {
                    transientRule.setScheduleCron(request.scheduleCron());
                    transientRule.setScheduleSkipUnchanged(request.scheduleSkipUnchanged());
                }

                try {
                    return qm.updateNotificationRule(transientRule);
                } catch (IllegalArgumentException e) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity(e.getMessage())
                            .build());
                }
            });

            qm.makeTransient(persisted);
            persisted.setProjects(filterAccessibleProjects(persisted.getProjects()));
            updatedRule = persisted;
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated notification rule '{}'", updatedRule.getName());

        return Response.ok(updatedRule).build();
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Notification rule removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification rule could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteNotificationRule(NotificationRule jsonRule) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, jsonRule.getUuid());
                if (rule != null) {
                    qm.delete(rule);
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification rule could not be found.").build();
                }
            });
        }
    }

    @POST
    @Path("/{ruleUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Adds a project to a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule already has the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The notification rule or project could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response addProjectToRule(
            @Parameter(description = "The UUID of the rule to add a project to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final NotificationRule updatedRule = qm.callInTransaction(() -> {
                final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
                if (rule == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The notification rule could not be found.")
                            .build());
                }
                if (rule.getScope() != NotificationScope.PORTFOLIO) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_ACCEPTABLE)
                            .entity("Project limitations are only possible on notification rules with PORTFOLIO scope.")
                            .build());
                }
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build());
                }
                requireAccess(qm, project);
                final List<Project> projects = rule.getProjects();
                if (projects == null || projects.contains(project)) {
                    return null;
                }
                rule.getProjects().add(project);
                return rule;
            });
            if (updatedRule == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedRule);
            updatedRule.setProjects(filterAccessibleProjects(updatedRule.getProjects()));
            return Response.ok(updatedRule).build();
        }
    }

    @DELETE
    @Path("/{ruleUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Removes a project from a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification rule",
                    content = @Content(schema = @Schema(implementation = NotificationRule.class))
            ),
            @ApiResponse(responseCode = "304", description = "The rule does not have the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The notification rule or project could not be found")
    })
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_DELETE})
    public Response removeProjectFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final NotificationRule updatedRule = qm.callInTransaction(() -> {
                final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
                if (rule == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The notification rule could not be found.")
                            .build());
                }
                if (rule.getScope() != NotificationScope.PORTFOLIO) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_ACCEPTABLE)
                            .entity("Project limitations are only possible on notification rules with PORTFOLIO scope.")
                            .build());
                }
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build());
                }
                requireAccess(qm, project);
                final List<Project> projects = rule.getProjects();
                if (projects == null || !projects.contains(project)) {
                    return null;
                }
                rule.getProjects().remove(project);
                return rule;
            });
            if (updatedRule == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedRule);
            updatedRule.setProjects(filterAccessibleProjects(updatedRule.getProjects()));
            return Response.ok(updatedRule).build();
        }
    }

    @POST
    @Path("/{ruleUuid}/team/{teamUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Adds a team to a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
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
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE})
    public Response addTeamToRule(
            @Parameter(description = "The UUID of the rule to add a team to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the team to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final NotificationRule updatedRule = qm.callInTransaction(() -> {
                final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
                if (rule == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The notification rule could not be found.")
                            .build());
                }
                final Team team = qm.getObjectByUuid(Team.class, teamUuid);
                if (team == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The team could not be found.")
                            .build());
                }
                final Set<Team> teams = rule.getTeams();
                if (teams == null || teams.contains(team)) {
                    return null;
                }
                rule.getTeams().add(team);
                return rule;
            });
            if (updatedRule == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedRule);
            updatedRule.setProjects(filterAccessibleProjects(updatedRule.getProjects()));
            return Response.ok(updatedRule).build();
        }
    }

    @DELETE
    @Path("/{ruleUuid}/team/{teamUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Removes a team from a notification rule",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
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
    @PermissionRequired({Permissions.Constants.SYSTEM_CONFIGURATION, Permissions.Constants.SYSTEM_CONFIGURATION_DELETE})
    public Response removeTeamFromRule(
            @Parameter(description = "The UUID of the rule to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("ruleUuid") @ValidUuid String ruleUuid,
            @Parameter(description = "The UUID of the project to remove from the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final NotificationRule updatedRule = qm.callInTransaction(() -> {
                final NotificationRule rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
                if (rule == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The notification rule could not be found.")
                            .build());
                }
                final Team team = qm.getObjectByUuid(Team.class, teamUuid);
                if (team == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The team could not be found.")
                            .build());
                }
                final Set<Team> teams = rule.getTeams();
                if (teams == null || !teams.contains(team)) {
                    return null;
                }
                rule.getTeams().remove(team);
                return rule;
            });
            if (updatedRule == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedRule);
            updatedRule.setProjects(filterAccessibleProjects(updatedRule.getProjects()));
            return Response.ok(updatedRule).build();
        }
    }

}
