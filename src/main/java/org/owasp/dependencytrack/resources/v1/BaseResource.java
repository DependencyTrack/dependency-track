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
package org.owasp.dependencytrack.resources.v1;

import org.owasp.dependencytrack.model.LdapUser;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import java.security.Principal;

abstract class BaseResource {

    @Context
    ContainerRequestContext requestContext;

    /**
     * Returns the principal for who initiated the request.
     * @see {@link org.owasp.dependencytrack.model.ApiKey}
     * @see {@link org.owasp.dependencytrack.model.LdapUser}
     */
    protected Principal getPrincipal() {
        Object principal = requestContext.getProperty("Principal");
        if (principal != null) {
            return (Principal)principal;
        } else {
            return null;
        }
    }

    protected boolean isLdapUser() {
        return (getPrincipal() instanceof LdapUser);
    }

}
