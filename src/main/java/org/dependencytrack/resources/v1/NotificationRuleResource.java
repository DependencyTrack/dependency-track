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
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
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

/**
 * JAX-RS resources for processing notification rules.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/notification/rule")
@Api(authorizations = @Authorization(value = "X-Api-Key"))
public class NotificationRuleResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(NotificationRuleResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all notification rules",
            response = NotificationRule.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of notification rules")

    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Creates a new notification rule",
            response = NotificationRule.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the notification publisher could not be found")
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
    @ApiOperation(
            value = "Updates a notification rule",
            response = NotificationRule.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the notification rule could not be found")
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
    @ApiOperation(
            value = "Deletes a notification rule",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the notification rule could not be found")
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
    @ApiOperation(
            value = "Adds a project to a notification rule",
            response = NotificationRule.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The rule already has the specified project assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response addProjectToRule(
            @ApiParam(value = "The UUID of the rule to add a project to", required = true)
            @PathParam("ruleUuid") String ruleUuid,
            @ApiParam(value = "The UUID of the project to add to the rule", required = true)
            @PathParam("projectUuid") String projectUuid) {
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
    @ApiOperation(
            value = "Removes a project from a notification rule",
            response = NotificationRule.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The rule does not have the specified project assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The notification rule or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response removeProjectFromRule(
            @ApiParam(value = "The UUID of the rule to remove the project from", required = true)
            @PathParam("ruleUuid") String ruleUuid,
            @ApiParam(value = "The UUID of the project to remove from the rule", required = true)
            @PathParam("projectUuid") String projectUuid) {
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
}
