/*
 * This file is part of Alpine.
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
package alpine.server.resources;

import alpine.common.validation.ValidationException;
import alpine.common.validation.ValidationTask;
import alpine.model.ApiKey;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.resources.AlpineRequest;
import alpine.server.filters.AuthorizationFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.glassfish.jersey.server.validation.ValidationError;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A value-added resource that all Alpine resources should extend from. This resource provides
 * access to pagination, ordering, filtering, convenience methods for obtaining specific HTTP
 * request information, along with the ability to perform input validation and automatically
 * fail requests (with HTTP status 400) if validation failure occurs.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public abstract class AlpineResource {

    private static final ValidatorFactory VALIDATOR_FACTORY = Validation.buildDefaultValidatorFactory();

    protected static final String TOTAL_COUNT_HEADER = "X-Total-Count";

    @Context
    private ContainerRequestContext requestContext;

    @Context
    private HttpServletRequest request;

    @Context
    private UriInfo uriInfo;

    private AlpineRequest alpineRequest;


    /**
     * Returns the ContainerRequestContext. This is automatically injected
     * into every instance of an AlpineResource.
     * @return the ContainerRequestContext
     * @since 1.0.0
     */
    protected ContainerRequestContext getRequestContext() {
        return requestContext;
    }

    /**
     * Returns the UriInfo. This is automatically injected into every
     * instance of an AlpineResource.
     * @return the UriInfo
     * @since 1.0.0
     */
    protected UriInfo getUriInfo() {
        return uriInfo;
    }

    /**
     * Returns the AlpineRequest object containing pagination, order,
     * filters, and other Alpine-specified aspects of the request.
     * @return a AlpineRequest object
     * @since 1.0.0
     */
    protected AlpineRequest getAlpineRequest() {
        final Object alpineRequest = requestContext.getProperty("AlpineRequest");
        if (alpineRequest != null) {
            return (AlpineRequest) alpineRequest;
        } else {
            return null;
        }
    }

    /**
     * Convenience method that returns the remote IP address that made
     * the request.
     * @return the remote IP address as a String
     * @since 1.0.0
     */
    protected String getRemoteAddress() {
        return request.getRemoteAddr();
    }

    /**
     * Convenience method that returns the remote hostname that made
     * the request.
     * @return the remote hostname as a String
     * @since 1.0.0
     */
    protected String getRemoteHost() {
        return request.getRemoteHost();
    }

    /**
     * Convenience method that returns the User-Agent string for the
     * application that made the request.
     * @return the User-Agent as a String
     * @since 1.0.0
     */
    protected String getUserAgent() {
        return requestContext.getHeaderString("User-Agent");
    }

    /**
     * Returns a Validator instance. Internally, this uses
     * Validation.buildDefaultValidatorFactory().getValidator() so only call
     * this method sparingly and keep a reference to the Validator if possible.
     * @return a Validator object
     * @since 1.0.0
     */
    protected Validator getValidator() {
        return VALIDATOR_FACTORY.getValidator();
    }

    /**
     * Accepts the result from one of the many validation methods available and
     * returns a List of ValidationErrors. If the size of the List is 0, no errors
     * were encounter during validation.
     *
     * Usage:
     * <pre>
     *     Validator validator = getValidator();
     *     List&lt;ValidationError&gt; errors = contOnValidationError(
     *         validator.validateProperty(myObject, "uuid"),
     *         validator.validateProperty(myObject, "name")
     *      );
     *      // If validation fails, this line will be reached.
     * </pre>
     *
     * @param violationsArray a Set of one or more ConstraintViolations
     * @return a List of zero or more ValidationErrors
     * @since 1.0.0
     */
    @SafeVarargs
    protected final List<ValidationError> contOnValidationError(final Set<ConstraintViolation<Object>>... violationsArray) {
        final List<ValidationError> errors = new ArrayList<>();
        for (final Set<ConstraintViolation<Object>> violations : violationsArray) {
            for (final ConstraintViolation violation : violations) {
                if (violation.getPropertyPath().iterator().next().getName() != null) {
                    final String path = violation.getPropertyPath() != null ? violation.getPropertyPath().toString() : null;
                    final String rawMessage = violation.getMessage();
                    final String prefix = path + ".";
                    final String message = rawMessage != null && rawMessage.startsWith(prefix)
                            ? rawMessage.substring(prefix.length())
                            : rawMessage;
                    final String messageTemplate = violation.getMessageTemplate();
                    final String invalidValue = violation.getInvalidValue() != null ? violation.getInvalidValue().toString() : null;
                    final ValidationError error = new ValidationError(message, messageTemplate, path, invalidValue);
                    errors.add(error);
                }
            }
        }
        return errors;
    }

    /**
     * Wrapper around {@link #contOnValidationError(Set[])} but instead of returning
     * a list of errors, this method will halt processing of the request by throwing
     * a BadRequestException, setting the HTTP status to 400 (BAD REQUEST) and providing
     * a full list of validation errors in the body of the response.
     *
     * Usage:
     * <pre>
     *     Validator validator = getValidator();
     *     failOnValidationError(
     *         validator.validateProperty(myObject, "uuid"),
     *         validator.validateProperty(myObject, "name")
     *      );
     *      // If validation fails, this line will not be reached.
     * </pre>
     *
     * @param violationsArray a Set of one or more ConstraintViolations
     * @since 1.0.0
     */
    @SafeVarargs
    protected final void failOnValidationError(final Set<ConstraintViolation<Object>>... violationsArray) {
        final List<ValidationError> errors = contOnValidationError(violationsArray);
        if (!errors.isEmpty()) {
            throw new BadRequestException(Response.status(Response.Status.BAD_REQUEST).entity(errors).build());
        }
    }

    /**
     * Given one or mote ValidationTasks, this method will return a List of
     * ValidationErrors. If the size of the List is 0, no errors were encountered
     * during validation.
     *
     * Usage:
     * <pre>
     *     List&lt;ValidationException&gt; errors = contOnValidationError(
     *         new ValidationTask(pattern, input, errorMessage),
     *         new ValidationTask(pattern, input, errorMessage)
     *      );
     *      // If validation fails, this line will be reached.
     * </pre>
     *
     * @param validationTasks an array of one or more ValidationTasks
     * @return a List of zero or more ValidationException
     * @since 1.0.0
     */
    protected final List<ValidationException> contOnValidationError(final ValidationTask... validationTasks) {
        final List<ValidationException> errors = new ArrayList<>();
        for (final ValidationTask validationTask:  validationTasks) {
            if (!validationTask.isRequired() && validationTask.getInput() == null) {
                continue;
            }
            if (!validationTask.getPattern().matcher(validationTask.getInput()).matches()) {
                errors.add(new ValidationException(validationTask.getInput(), validationTask.getErrorMessage()));
            }
        }
        return errors;
    }

    /**
     * Wrapper around {@link #contOnValidationError(ValidationTask[])} but instead of returning
     * a list of errors, this method will halt processing of the request by throwing
     * a BadRequestException, setting the HTTP status to 400 (BAD REQUEST) and providing
     * a full list of validation errors in the body of the response.
     *
     * Usage:
     * <pre>
     *     List&lt;ValidationException&gt; errors = failOnValidationError(
     *         new ValidationTask(pattern, input, errorMessage),
     *         new ValidationTask(pattern, input, errorMessage)
     *      );
     *      // If validation fails, this line will not be reached.
     * </pre>
     *
     * @param validationTasks an array of one or more ValidationTasks
     * @since 1.0.0
     */
    protected final void failOnValidationError(final ValidationTask... validationTasks) {
        final List<ValidationException> errors = contOnValidationError(validationTasks);
        if (!errors.isEmpty()) {
            throw new BadRequestException(Response.status(Response.Status.BAD_REQUEST).entity(errors).build());
        }
    }

    /**
     * Returns the principal for who initiated the request.
     * @return a Principal object
     * @see alpine.model.ApiKey
     * @see alpine.model.LdapUser
     * @since 1.0.0
     */
    protected Principal getPrincipal() {
        final Object principal = requestContext.getProperty("Principal");
        if (principal != null) {
            return (Principal) principal;
        } else {
            return null;
        }
    }

    protected boolean isOidcUser() {
        return getPrincipal() instanceof OidcUser;
    }

    /**
     * @return true is the current Principal is an instance of LdapUser. False if not.
     * @since 1.0.0
     */
    protected boolean isLdapUser() {
        return getPrincipal() instanceof LdapUser;
    }

    /**
     * @return true is the current Principal is an instance of ManagedUser. False if not.
     * @since 1.0.0
     */
    protected boolean isManagedUser() {
        return getPrincipal() instanceof ManagedUser;
    }

    /**
     * @return true is the current Principal is an instance of ApiKey. False if not.
     * @since 1.0.0
     */
    protected boolean isApiKey() {
        return getPrincipal() instanceof ApiKey;
    }

    /**
     * Convenience method that returns true if the principal has the specified permission,
     * or false if not.
     * @param permission the permission to check
     * @return true if principal has permission assigned, false if not
     * @since 1.2.0
     */
    protected boolean hasPermission(final String permission) {
        final Set<String> effectivePermissions = getEffectivePermissions();
        return effectivePermissions != null && effectivePermissions.contains(permission);
    }

    /**
     * @since 3.2.0
     */
    @SuppressWarnings("unchecked")
    protected Set<String> getEffectivePermissions() {
        return (Set<String>) requestContext.getProperty(
                AuthorizationFilter.EFFECTIVE_PERMISSIONS_PROPERTY);
    }

    /**
     * Logs a security event to the security audit log. Expects one of:
     * {@link SecurityMarkers#SECURITY_AUDIT}
     * {@link SecurityMarkers#SECURITY_SUCCESS}
     * {@link SecurityMarkers#SECURITY_FAILURE}
     * @param logger the logger to use
     * @param marker the marker to add to the event
     * @param message the initial content of the event
     * @since 1.0.0
     */
    protected void logSecurityEvent(final Logger logger, final Marker marker, final String message) {
        if (!(SecurityMarkers.SECURITY_AUDIT == marker ||
              SecurityMarkers.SECURITY_SUCCESS == marker ||
              SecurityMarkers.SECURITY_FAILURE == marker)) {
            return;
        }
        final StringBuilder sb = new StringBuilder();
        sb.append(message).append(" ");
        if (getPrincipal() != null) {
            sb.append("by: ").append(getPrincipal().getName()).append(" ");
        }
        sb.append("/ IP Address: ").append(getRemoteAddress()).append(" ");
        sb.append("/ User Agent: ").append(getUserAgent());
        logger.info(marker, sb.toString());
    }

}
