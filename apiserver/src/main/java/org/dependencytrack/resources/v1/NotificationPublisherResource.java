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

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.Schema.AdditionalPropertiesValue;
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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.MdcKeys;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.notification.PublishNotificationWorkflow;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Level;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Scope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.vo.CreateNotificationPublisherRequest;
import org.dependencytrack.resources.v1.vo.NotificationPublisherResponse;
import org.dependencytrack.resources.v1.vo.UpdateNotificationPublisherRequest;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_TRIGGERED_BY;
import static org.dependencytrack.notification.NotificationModelConverter.convert;
import static org.dependencytrack.notification.api.TestNotificationFactory.createTestNotification;

/**
 * JAX-RS resources for processing notification publishers.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/notification/publisher")
@Tag(name = "notification")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class NotificationPublisherResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationPublisherResource.class);

    private final PluginManager pluginManager;
    private final DexEngine dexEngine;

    @Inject
    NotificationPublisherResource(PluginManager pluginManager, DexEngine dexEngine) {
        this.pluginManager = pluginManager;
        this.dexEngine = dexEngine;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of all notification publishers",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all notification publishers",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = NotificationPublisherResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getAllNotificationPublishers() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final List<NotificationPublisherResponse> publishers =
                    qm.getAllNotificationPublishers().stream()
                            .map(NotificationPublisherResponse::of)
                            .toList();
            return Response.ok(publishers).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new notification publisher",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created notification publisher",
                    content = @Content(schema = @Schema(implementation = NotificationPublisherResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "Conflict with an existing publisher's name")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createNotificationPublisher(@Valid CreateNotificationPublisherRequest request) {
        requireExtensionExists(request.extensionName());

        final NotificationPublisher createdPublisher;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            createdPublisher = qm.callInTransaction(() -> {
                final NotificationPublisher existingPublisher = qm.getNotificationPublisher(request.name());
                if (existingPublisher != null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.CONFLICT)
                            .entity("The notification with the name " + request.name() + " already exist")
                            .build());
                }

                return qm.createNotificationPublisher(
                        request.name(),
                        request.description(),
                        request.extensionName(),
                        request.template(),
                        request.templateMimeType(),
                        /* defaultPublisher */ false);
            });
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Created notification publisher '{}'",
                createdPublisher.getName());

        return Response
                .status(Response.Status.CREATED)
                .entity(NotificationPublisherResponse.of(createdPublisher))
                .build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a notification publisher",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated notification publisher",
                    content = @Content(schema = @Schema(implementation = NotificationPublisherResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The notification publisher could not be found"),
            @ApiResponse(responseCode = "409", description = "Conflict with an existing publisher's name")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateNotificationPublisher(UpdateNotificationPublisherRequest request) {
        requireExtensionExists(request.extensionName());

        final NotificationPublisher updatedPublisher;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            updatedPublisher = qm.callInTransaction(() -> {
                final var publisher = qm.getObjectByUuid(NotificationPublisher.class, request.uuid());
                if (publisher == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the notification publisher could not be found.")
                            .build());
                }
                if (publisher.isDefaultPublisher()) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("The modification of a default publisher is forbidden")
                            .build());
                }

                if (!request.name().equals(publisher.getName())) {
                    final NotificationPublisher conflictingPublisher = qm.getNotificationPublisher(request.name());
                    if (conflictingPublisher != null) {
                        throw new ClientErrorException(Response
                                .status(Response.Status.CONFLICT)
                                .entity("An existing publisher with the name '" + conflictingPublisher.getName() + "' already exist")
                                .build());
                    }
                }
                publisher.setName(request.name());
                publisher.setDescription(request.description());
                publisher.setExtensionName(request.extensionName());
                publisher.setTemplate(request.template());
                publisher.setTemplateMimeType(request.templateMimeType());
                return publisher;
            });
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Updated notification publisher '{}'",
                updatedPublisher.getName());

        return Response
                .ok(NotificationPublisherResponse.of(updatedPublisher))
                .build();
    }

    @DELETE
    @Path("/{notificationPublisherUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a notification publisher and all related notification rules",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Notification publisher removed successfully"),
            @ApiResponse(responseCode = "400", description = "Deleting a default notification publisher is forbidden"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteNotificationPublisher(
            @Parameter(description = "The UUID of the notification publisher to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("notificationPublisherUuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final var publisher = qm.getObjectByUuid(NotificationPublisher.class, uuid);
                if (publisher != null) {
                    if (publisher.isDefaultPublisher()) {
                        return Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("Deleting a default notification publisher is forbidden.")
                                .build();
                    } else {
                        qm.delete(publisher);
                        return Response
                                .status(Response.Status.NO_CONTENT)
                                .build();
                    }
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the notification rule could not be found.")
                            .build();
                }
            });
        }
    }

    @GET
    @Path("/{uuid}/configSchema")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Get notification publisher config schema",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Publisher config JSON schema",
                    content = @Content(schema = @Schema(additionalProperties = AdditionalPropertiesValue.TRUE))),
            @ApiResponse(responseCode = "204", description = "Publisher has no configuration"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getNotificationPublisherConfigSchema(@PathParam("uuid") UUID uuid) {
        final String extensionName;
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final var publisher = qm.getObjectByUuid(NotificationPublisher.class, uuid);
            if (publisher != null) {
                extensionName = publisher.getExtensionName();
            } else {
                throw new ClientErrorException(Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The UUID of the notification publisher could not be found.")
                        .build());
            }
        }

        final NotificationPublisherFactory extensionFactory =
                requireExtensionExists(extensionName);

        final RuntimeConfigSpec ruleConfigSpec = extensionFactory.ruleConfigSpec();
        if (ruleConfigSpec == null) {
            return Response.noContent().build();
        }

        return Response.ok(ruleConfigSpec.schema()).build();
    }

    @POST
    @Path("/test/{uuid}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Dispatches a rule notification test",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Test notification dispatched successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "Notification rule not found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response testNotificationRule(
            @Parameter(description = "The UUID of the rule to test", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String ruleUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final var rule = qm.getObjectByUuid(NotificationRule.class, ruleUuid);
            if (rule == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            final var createRunRequests = new ArrayList<CreateWorkflowRunRequest<?>>();
            for (final var notificationGroup : rule.getNotifyOn()) {
                final Group group = convert(notificationGroup);
                final Notification notification = buildTestNotification(
                        convert(rule.getScope()), group, convert(rule.getNotificationLevel()));
                if (notification == null) {
                    continue;
                }

                final var workflowArg = PublishNotificationWorkflowArg.newBuilder()
                        .setNotificationId(notification.getId())
                        .setNotification(notification)
                        .addNotificationRuleNames(rule.getName())
                        .build();

                createRunRequests.add(
                        new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                                .withWorkflowInstanceId(
                                        "publish-test-notification:%s:%s".formatted(
                                                rule.getUuid(), notificationGroup))
                                .withLabels(Map.of(WF_LABEL_TRIGGERED_BY, getPrincipal().getName()))
                                .withArgument(workflowArg));
            }

            if (!createRunRequests.isEmpty()) {
                dexEngine.createRuns(createRunRequests);

                try (var _ = MDC.putCloseable(MdcKeys.MDC_NOTIFICATION_RULE_NAME, rule.getName())) {
                    LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Triggered test notification(s)");
                }
            }

            return Response.ok().build();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Exception occurred while sending the notification.")
                    .build();
        }
    }

    private NotificationPublisherFactory requireExtensionExists(String extensionName) {
        try {
            return pluginManager.getFactory(
                    org.dependencytrack.notification.api.publishing.NotificationPublisher.class,
                    extensionName);
        } catch (NoSuchExtensionException e) {
            throw new ClientErrorException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("No extension with name '%s' exists".formatted(extensionName))
                    .build());
        }
    }

    private @Nullable Notification buildTestNotification(Scope scope, Group group, Level ruleLevel) {
        final List<Level> levelsToTry = switch (ruleLevel) {
            case LEVEL_INFORMATIONAL -> List.of(Level.LEVEL_INFORMATIONAL, Level.LEVEL_WARNING, Level.LEVEL_ERROR);
            case LEVEL_WARNING -> List.of(Level.LEVEL_WARNING, Level.LEVEL_ERROR);
            case LEVEL_ERROR -> List.of(Level.LEVEL_ERROR);
            default -> List.of();
        };

        for (final Level level : levelsToTry) {
            final Notification notification = createTestNotification(scope, group, level);
            if (notification != null) {
                return notification.toBuilder()
                        .setTitle("[TEST] " + notification.getTitle())
                        .build();
            }
        }

        return null;
    }

}