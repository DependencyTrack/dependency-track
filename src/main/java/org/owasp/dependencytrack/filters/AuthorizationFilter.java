/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.filters;

import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.auth.PermissionRequired;
import org.owasp.dependencytrack.logging.Logger;
import org.glassfish.jersey.server.ContainerRequest;
import org.owasp.dependencytrack.model.LdapUser;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.security.Principal;

@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    // Setup logging
    private static final Logger logger = Logger.getLogger(AuthorizationFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (requestContext instanceof ContainerRequest) {

            Principal principal = (Principal) requestContext.getProperty("Principal");
            if (principal == null) {
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
                return;
            }

            PermissionRequired annotation = resourceInfo.getResourceMethod().getDeclaredAnnotation(PermissionRequired.class);

            try (QueryManager qm = new QueryManager()) {
                if (principal instanceof LdapUser) {
                    LdapUser user = qm.getLdapUser(((LdapUser) principal).getUsername());

                    Permission[] permissions = annotation.value();
                    for (Permission permission : permissions) {
                        // todo check if user has one of these required permissions
                    }
                }
            }
        }
    }

}