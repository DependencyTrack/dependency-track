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
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.*;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.json.Json;
import javax.json.JsonObject;
import javax.validation.Validator;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * JAX-RS resources for processing notification publishers.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/notification/publisher")
@Api(authorizations = @Authorization(value = "X-Api-Key"))
public class NotificationPublisherResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(NotificationPublisherResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all notification publishers",
            response = NotificationPublisher.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getAllNotificationPublishers() {
        try (QueryManager qm = new QueryManager()) {
            final List<NotificationPublisher> publishers = qm.getAllNotificationPublishers();
            return Response.ok(publishers).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new notification publisher",
            response = NotificationPublisher.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "Conflict with an existing publisher's name")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response createNotificationPublisher(NotificationPublisher jsonNotificationPublisher) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonNotificationPublisher, "name"),
                validator.validateProperty(jsonNotificationPublisher, "publisherClass"),
                validator.validateProperty(jsonNotificationPublisher, "description"),
                validator.validateProperty(jsonNotificationPublisher, "templateMimeType"),
                validator.validateProperty(jsonNotificationPublisher, "template")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher existingNotificationPublisher = qm.getNotificationPublisher(jsonNotificationPublisher.getName());
            if(existingNotificationPublisher != null) {
                return Response.status(Response.Status.CONFLICT).entity("The notification with the name "+jsonNotificationPublisher.getName()+" already exist").build();
            }

            if(jsonNotificationPublisher.isDefaultPublisher()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("The creation of a new default publisher is forbidden").build();
            }

            Class<?> publisherClass = Class.forName(jsonNotificationPublisher.getPublisherClass());

            if (Publisher.class.isAssignableFrom(publisherClass)) {
                Class<Publisher> castedPublisherClass = (Class<Publisher>) publisherClass;
                NotificationPublisher notificationPublisherCreated = qm.createNotificationPublisher(
                        jsonNotificationPublisher.getName(), jsonNotificationPublisher.getDescription(),
                        castedPublisherClass, jsonNotificationPublisher.getTemplate(), jsonNotificationPublisher.getTemplateMimeType(),
                        jsonNotificationPublisher.isDefaultPublisher()
                );
                return Response.status(Response.Status.CREATED).entity(notificationPublisherCreated).build();
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("The class "+jsonNotificationPublisher.getPublisherClass()+" does not implement "+Publisher.class.getName()).build();
            }

        } catch (ClassNotFoundException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The class "+jsonNotificationPublisher.getPublisherClass()+" cannot be found").build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a notification publisher",
            response = NotificationRule.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Invalid notification class or trying to modify a default publisher"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The notification publisher could not be found"),
            @ApiResponse(code = 409, message = "Conflict with an existing publisher's name")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateNotificationPublisher(NotificationPublisher jsonNotificationPublisher) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonNotificationPublisher, "name"),
                validator.validateProperty(jsonNotificationPublisher, "publisherClass"),
                validator.validateProperty(jsonNotificationPublisher, "description"),
                validator.validateProperty(jsonNotificationPublisher, "templateMimeType"),
                validator.validateProperty(jsonNotificationPublisher, "template"),
                validator.validateProperty(jsonNotificationPublisher, "uuid")
        );

        try (QueryManager qm = new QueryManager()) {
            NotificationPublisher existingPublisher = qm.getObjectByUuid(NotificationPublisher.class, jsonNotificationPublisher.getUuid());
            if (existingPublisher != null) {
                if(existingPublisher.isDefaultPublisher()) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The modification of a default publisher is forbidden").build();
                }

                if(!jsonNotificationPublisher.getName().equals(existingPublisher.getName())) {
                    NotificationPublisher existingNotificationPublisherWithModifiedName = qm.getNotificationPublisher(jsonNotificationPublisher.getName());
                    if(existingNotificationPublisherWithModifiedName != null) {
                        return Response.status(Response.Status.CONFLICT).entity("An existing publisher with the name '"+existingNotificationPublisherWithModifiedName.getName()+"' already exist").build();
                    }
                }
                existingPublisher.setName(jsonNotificationPublisher.getName());
                existingPublisher.setDescription(jsonNotificationPublisher.getDescription());

                Class<?> publisherClass = Class.forName(jsonNotificationPublisher.getPublisherClass());

                if (Publisher.class.isAssignableFrom(publisherClass)) {
                    existingPublisher.setPublisherClass(jsonNotificationPublisher.getPublisherClass());
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The class "+jsonNotificationPublisher.getPublisherClass()+" does not implement "+Publisher.class.getCanonicalName()).build();
                }
                existingPublisher.setTemplate(jsonNotificationPublisher.getTemplate());
                existingPublisher.setTemplateMimeType(jsonNotificationPublisher.getTemplateMimeType());
                existingPublisher.setDefaultPublisher(false);
                NotificationPublisher notificationPublisherUpdated = qm.updateNotificationPublisher(existingPublisher);
                return Response.ok(notificationPublisherUpdated).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification publisher could not be found.").build();
            }
        } catch (ClassNotFoundException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The class "+jsonNotificationPublisher.getPublisherClass()+" cannot be found").build();
        }
    }

    @DELETE
    @Path("/{notificationPublisherUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a notification publisher and all related notification rules",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Deleting a default notification publisher is forbidden"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the notification publisher could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteNotificationPublisher(@ApiParam(value = "The UUID of the notification publisher to delete", required = true)
                                               @PathParam("notificationPublisherUuid") String notificationPublisherUuid) {
        try (QueryManager qm = new QueryManager()) {
            final NotificationPublisher notificationPublisher = qm.getObjectByUuid(NotificationPublisher.class, notificationPublisherUuid);
            if (notificationPublisher != null) {
                if(notificationPublisher.isDefaultPublisher()) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Deleting a default notification publisher is forbidden.").build();
                } else {
                    qm.deleteNotificationPublisher(notificationPublisher);
                    return Response.status(Response.Status.NO_CONTENT).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the notification rule could not be found.").build();
            }
        }
    }

    @POST
    @Path("/restoreDefaultTemplates")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Restore the default notification publisher templates using the ones in the solution classpath"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response restoreDefaultTemplates() {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getGroupName(),
                    ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyName()
            );
            property.setPropertyValue("false");
            qm.persist(property);
            NotificationUtil.loadDefaultNotificationPublishers(qm);
            return Response.ok().build();
        } catch (IOException ioException) {
            LOGGER.error(ioException.getMessage(), ioException);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Exception occured while restoring default notification publisher templates.").build();
        }
    }

    @POST
    @Path("/test/smtp")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Dispatches a SMTP notification test"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response testSmtpPublisherConfig(@FormParam("destination") String destination) {
        try(QueryManager qm = new QueryManager()) {
            Class defaultEmailPublisherClass = SendMailPublisher.class;
            NotificationPublisher emailNotificationPublisher = qm.getDefaultNotificationPublisher(defaultEmailPublisherClass);
            final Publisher emailPublisher = (Publisher) defaultEmailPublisherClass.getDeclaredConstructor().newInstance();
            final JsonObject config = Json.createObjectBuilder()
                    .add(Publisher.CONFIG_DESTINATION, destination)
                    .add(Publisher.CONFIG_TEMPLATE_KEY, emailNotificationPublisher.getTemplate())
                    .add(Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY, emailNotificationPublisher.getTemplateMimeType())
                    .build();
            final Notification notification = new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.CONFIGURATION)
                    .title(NotificationConstants.Title.NOTIFICATION_TEST)
                    .content("SMTP configuration test")
                    .level(NotificationLevel.INFORMATIONAL);
            // Bypass Notification.dispatch() and go directly to the publisher itself
            emailPublisher.inform(notification, config);
            return Response.ok().build();
        } catch (InvocationTargetException | InstantiationException | IllegalAccessException | NoSuchMethodException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Exception occured while sending test mail notification.").build();
        }
    }
}
