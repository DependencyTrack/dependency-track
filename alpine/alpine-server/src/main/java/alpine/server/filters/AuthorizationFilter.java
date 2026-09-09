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
package alpine.server.filters;

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.Principal;
import alpine.model.auth.UserPrincipal;
import alpine.server.auth.PermissionRequired;
import jakarta.annotation.Priority;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Set;

/**
 * A filter that ensures that all principals making calls that are going
 * through this filter have the necessary permissions to do so.
 *
 * @author Steve Springett
 * @see AuthFeature
 * @since 1.0.0
 */
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        // Bypass authorization for CORS preflight.
        // AuthenticationFilter does the same, so no principal is available to authorize against.
        if (HttpMethod.OPTIONS.equals(requestContext.getMethod())) {
            return;
        }

        if (!(requestContext.getSecurityContext().getUserPrincipal() instanceof final Principal principal)) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "A request was made without the assertion of a valid user principal");
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }

        final PermissionRequired annotation = resourceInfo.getResourceMethod().getDeclaredAnnotation(PermissionRequired.class);
        if (annotation == null) {
            return;
        }

        if (!Collections.disjoint(Set.of(annotation.value()), principal.effectivePermissions())) {
            return;
        }

        final String principalDescription = switch (principal) {
            case ApiKeyPrincipal apiKey -> "API Key " + apiKey.maskedKey();
            case UserPrincipal user -> user.username();
        };

        LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Unauthorized access attempt made by %s to %s"
                .formatted(principalDescription, requestContext.getUriInfo().getRequestUri().toString()));

        throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
    }

}
